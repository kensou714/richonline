#include "storage.hpp"
#include <sqlite3.h>
#include <chrono>
#include <future>
#include <iostream>
#include <latch>
#include <memory>

namespace {
using namespace richnet;
using Json = nlohmann::json;
using Bytes = std::vector<std::uint8_t>;
void check(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
Bytes bytes(std::string_view text) { return {text.begin(),text.end()}; }
struct Fixture {
    std::filesystem::path path = std::filesystem::absolute("storage-login-test-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3");
    Storage storage{path};
    std::int64_t scalar(const char* query) const {
        sqlite3* raw = nullptr;
        const auto encoded = path.u8string();
        check(sqlite3_open_v2(reinterpret_cast<const char*>(encoded.c_str()),&raw,SQLITE_OPEN_READONLY,nullptr) == SQLITE_OK,
            "fixture_read_open_failed");
        std::unique_ptr<sqlite3,decltype(&sqlite3_close)> db(raw,sqlite3_close);
        sqlite3_stmt* statement = nullptr;
        check(sqlite3_prepare_v2(db.get(),query,-1,&statement,nullptr) == SQLITE_OK,"fixture_query_failed");
        std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)> row(statement,sqlite3_finalize);
        check(sqlite3_step(row.get()) == SQLITE_ROW,"fixture_row_missing");
        return sqlite3_column_int64(row.get(),0);
    }
    void registration(bool enabled) {
        auto config = storage.dispatch("config.get",Json::object());
        config["settings"]["registration_enabled"] = enabled;
        storage.dispatch("config.update",{{"expectedRevision",config.at("revision")},{"settings",config.at("settings")}});
    }
};
void first_login_uses_configured_assets_and_preserves_skills() {
    Fixture fixture;
    auto config = fixture.storage.dispatch("config.get",Json::object());
    auto& defaults = config["settings"]["default_role"];
    defaults["mpoints"] = 3456.5; defaults["gold"] = 432.25; defaults["bank"] = 99.5;
    defaults["level"] = 8; defaults["experience"] = 789; defaults["model"] = 2; defaults["vip_level"] = 1;
    config["settings"]["max_building_skills"][0] = 6;
    fixture.storage.dispatch("config.update",{{"expectedRevision",config.at("revision")},{"settings",config.at("settings")}});
    check(fixture.storage.login("NewPlayer",bytes("synthetic-first")) == LoginOutcome::registered,"first_login_not_registered");
    const auto role = fixture.storage.roles_for_username("NewPlayer").at(0);
    check(role.at("role_id") == 1 && role.at("name") == "NewPlayer" && role.at("model") == 2 && role.at("vip_level") == 1 &&
        role.at("coins") == 3456.5 && role.at("gold") == 432.25 && role.at("bank") == 99.5 &&
        role.at("level") == 8 && role.at("experience") == 789,"registration_defaults_lost");
    check(fixture.storage.dispatch("config.get",Json::object()).at("settings") == config.at("settings"),"registration_changed_skills_or_settings");
    check(fixture.scalar("SELECT count(*) FROM audit WHERE field='account_created' AND source='login'") == 1,"login_audit_source_wrong");
    check(fixture.scalar("SELECT value FROM metadata WHERE key='next_role_id'") == 2,"next_role_not_advanced");
    check(fixture.storage.login("NewPlayer",bytes("synthetic-first")) == LoginOutcome::authenticated,"repeat_login_failed");
    check(fixture.storage.login("NewPlayer",bytes("other-synthetic")) == LoginOutcome::password_mismatch,"wrong_password_overwrote_account");
    check(fixture.storage.roles_for_username("NewPlayer").at(0) == role,"repeat_login_changed_role");
    check(fixture.scalar("SELECT count(*) FROM audit WHERE field='account_created'") == 1,"repeat_login_audited_creation");
}
void disabled_registration_preserves_existing_login_and_admin_create() {
    Fixture fixture;
    fixture.storage.dispatch("accounts.create",{{"username","Managed"},{"password","managed-fixture"}});
    fixture.registration(false);
    check(fixture.storage.login("Managed",bytes("managed-fixture")) == LoginOutcome::authenticated,"disabled_registration_blocks_existing");
    check(fixture.storage.login("Managed",bytes("wrong-fixture")) == LoginOutcome::password_mismatch,"disabled_registration_masks_mismatch");
    check(fixture.storage.login("Absent",bytes("new-fixture")) == LoginOutcome::registration_disabled,"disabled_registration_created_user");
    check(fixture.scalar("SELECT count(*) FROM accounts") == 1 &&
        fixture.scalar("SELECT value FROM metadata WHERE key='next_role_id'") == 2,"disabled_registration_wrote_account");
    fixture.storage.dispatch("accounts.create",{{"username","AnotherManaged"},{"password","another-fixture"}});
    check(fixture.scalar("SELECT count(*) FROM audit WHERE field='account_created' AND source='native-admin'") == 2,"admin_create_semantics_changed");
}
void raw_password_bytes_are_not_reencoded() {
    Fixture fixture;
    const Bytes raw{0xff,0x80,0xfe,0x81};
    check(fixture.storage.login("RawPassword",raw) == LoginOutcome::registered,"raw_password_rejected");
    check(fixture.storage.verify_credentials("RawPassword",raw),"raw_password_bytes_changed");
    check(fixture.storage.login("RawPassword",Bytes{0xef,0xbf,0xbd}) == LoginOutcome::password_mismatch,"raw_password_normalized");
}
void invalid_credentials_never_create_accounts() {
    Fixture fixture;
    for (const auto& password : std::vector<Bytes>{{},Bytes{1,0,2},Bytes(64,'x')})
        check(fixture.storage.login("InvalidPassword",password) == LoginOutcome::invalid_credentials,"invalid_password_accepted");
    for (const auto& username : std::vector<std::string>{"",std::string(32,'x'),std::string("a\0b",3),"😀",std::string("\xff",1)})
        check(fixture.storage.login(username,bytes("fixture")) == LoginOutcome::invalid_credentials,"invalid_username_accepted");
    check(fixture.scalar("SELECT count(*) FROM accounts") == 0 && fixture.scalar("SELECT count(*) FROM audit") == 0 &&
        fixture.scalar("SELECT value FROM metadata WHERE key='next_role_id'") == 1,"invalid_credentials_wrote_database");
    check(fixture.storage.login(std::string(31,'x'),Bytes(63,'p')) == LoginOutcome::registered,"valid_length_boundary_rejected");
}
void concurrent_first_logins_register_once() {
    Fixture fixture;
    std::latch ready(2), start(1);
    const auto attempt = [&](const char* password) {
        ready.count_down(); start.wait(); return fixture.storage.login("Concurrent",bytes(password));
    };
    auto first = std::async(std::launch::async,attempt,"first-fixture");
    auto second = std::async(std::launch::async,attempt,"second-fixture");
    ready.wait(); start.count_down();
    const auto a = first.get(), b = second.get();
    check((a == LoginOutcome::registered && b == LoginOutcome::password_mismatch) ||
        (b == LoginOutcome::registered && a == LoginOutcome::password_mismatch),"concurrent_registration_outcomes_wrong");
    check(fixture.scalar("SELECT count(*) FROM accounts") == 1 && fixture.scalar("SELECT count(*) FROM roles") == 1 &&
        fixture.scalar("SELECT count(*) FROM audit WHERE field='account_created' AND source='login'") == 1 &&
        fixture.scalar("SELECT value FROM metadata WHERE key='next_role_id'") == 2,"concurrent_registration_wrote_twice");
    check(fixture.storage.login("Concurrent",bytes(a == LoginOutcome::registered ? "first-fixture" : "second-fixture")) ==
        LoginOutcome::authenticated,"concurrent_winner_password_lost");
}
}
int main() {
    try {
        first_login_uses_configured_assets_and_preserves_skills();
        disabled_registration_preserves_existing_login_and_admin_create();
        raw_password_bytes_are_not_reencoded(); invalid_credentials_never_create_accounts();
        concurrent_first_logins_register_once();
        std::cout << "storage login tests PASS\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
