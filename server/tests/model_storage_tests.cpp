#include "storage.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <chrono>
#include <iostream>
#include <limits>
#include <memory>
#include <string_view>

namespace {
using nlohmann::json;
void check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}
class Database {
public:
    explicit Database(const std::filesystem::path& path) {
        sqlite3* raw = nullptr;
        const auto encoded = path.u8string();
        const int status = sqlite3_open(reinterpret_cast<const char*>(encoded.c_str()), &raw);
        db_.reset(raw);
        check(status == SQLITE_OK, "open model fixture");
        check(sqlite3_busy_timeout(db_.get(), 5000) == SQLITE_OK, "set fixture timeout");
    }
    void exec(const char* sql) {
        check(sqlite3_exec(db_.get(), sql, nullptr, nullptr, nullptr) == SQLITE_OK, "fixture SQL");
    }
    json rows(const char* sql) {
        sqlite3_stmt* raw = nullptr;
        const int prepared = sqlite3_prepare_v2(db_.get(), sql, -1, &raw, nullptr);
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> statement(raw, sqlite3_finalize);
        check(prepared == SQLITE_OK, "prepare fixture query");
        auto result = json::array();
        int status;
        while ((status = sqlite3_step(statement.get())) == SQLITE_ROW) {
            auto row = json::array();
            for (int column = 0; column < sqlite3_column_count(statement.get()); ++column) {
                const auto* value = sqlite3_column_text(statement.get(), column);
                row.push_back(value ? json(reinterpret_cast<const char*>(value)) : json(nullptr));
            }
            result.push_back(row);
        }
        check(status == SQLITE_DONE, "finish fixture query");
        return result;
    }
private:
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> db_{nullptr, sqlite3_close};
};
struct Fixture {
    std::filesystem::path path;
    richnet::Storage store;
    std::int64_t role_id;
    explicit Fixture(const std::filesystem::path& file) : path(file),
        store(file, richnet::ClientProfile::original),
        role_id(store.dispatch("accounts.create", {{"username", "ModelOwner"},
            {"password", "model-test"}}).at("account").at("role_id").get<std::int64_t>()) {
        Database(path).exec("UPDATE roles SET model=2,level=7,experience=125,coins=5.5,gold=200.25,"
            "bank=100.5,wins=3,losses=4,draws=5,vip_level=2,escapes=6,purchase_score=7");
    }
    json role() { return store.roles_for_username("ModelOwner").at(0); }
    json state() {
        Database db(path);
        return json::array({db.rows("SELECT * FROM roles ORDER BY role_id"),
            db.rows("SELECT * FROM audit ORDER BY id"), db.rows("SELECT * FROM operations ORDER BY operation_id")});
    }
    json select(std::uint32_t model) { return store.select_model("ModelOwner", role_id, model); }
};
template<class Action>
void rejects(Action action, std::string_view code) {
    try { action(); }
    catch (const richnet::StorageError& error) {
        check(error.what() == code, "wrong model rejection code");
        return;
    }
    throw std::runtime_error("expected model rejection missing");
}
void success_and_reopen(const std::filesystem::path& path) {
    json expected;
    {
        Fixture fixture(path);
        expected = fixture.role();
        expected["model"] = 4;
        check(fixture.select(4) == expected, "selection returns full committed role preserving unrelated fields");
        check(Database(path).rows("SELECT role_id,username,field,old_value,new_value,source,reason,operation_id "
            "FROM audit WHERE source='native-lobby'") == json::array({json::array({"1", "ModelOwner", "model",
            "2", "4", "native-lobby", "client model selection", ""})}), "selection audit identifies exact movement and owner");
        check(Database(path).rows("SELECT count(*) FROM operations") == json::array({json::array({"0"})}),
              "selection creates no deduplication operation");
    }
    richnet::Storage reopened(path, richnet::ClientProfile::original);
    check(reopened.roles_for_username("ModelOwner").at(0) == expected, "selection survives database reopen");
}
void repeated_selection(const std::filesystem::path& path) {
    Fixture fixture(path);
    const auto unchanged = fixture.state();
    check(fixture.select(2) == fixture.role(), "current model returns full role");
    check(fixture.state() == unchanged, "current model performs no data or audit writes");
    const auto selected = fixture.select(0);
    const auto changed = fixture.state();
    check(fixture.select(0) == selected && fixture.state() == changed, "repeated selection is idempotent");
    for (std::uint32_t model = 1; model <= 4; ++model)
        check(fixture.select(model).at("model") == model, "all five supported models accepted");
}
void ownership_and_range(const std::filesystem::path& path) {
    Fixture fixture(path);
    fixture.store.dispatch("accounts.create", {{"username", "OtherOwner"}, {"password", "other-test"}});
    const auto before = fixture.state();
    for (const auto* username : {"OtherOwner", "missing", "modelowner"})
        rejects([&] { fixture.store.select_model(username, fixture.role_id, 3); }, "model_role_not_owned");
    for (const std::int64_t role_id : {-1, 0, 999})
        rejects([&] { fixture.store.select_model("ModelOwner", role_id, 3); }, "model_role_not_owned");
    for (const auto model : {5U, (std::numeric_limits<std::uint32_t>::max)()})
        rejects([&] { fixture.select(model); }, "model_selection_invalid");
    check(fixture.state() == before, "ownership and range failures leave all roles and audit untouched");
}
void audit_rollback(const std::filesystem::path& path) {
    Fixture fixture(path);
    Database(path).exec("CREATE TRIGGER reject_model_audit BEFORE INSERT ON audit "
        "WHEN NEW.source='native-lobby' BEGIN SELECT RAISE(ABORT,'injected_model_audit_failure'); END;");
    const auto before = fixture.state();
    bool rejected = false;
    try { fixture.select(3); }
    catch (const richnet::StorageError&) { rejected = true; }
    check(rejected, "audit insertion failure rejects selection");
    check(fixture.state() == before, "audit failure rolls back model update");
    Database(path).exec("DROP TRIGGER reject_model_audit");
    check(fixture.select(3).at("model") == 3, "storage remains usable after rollback");
}
void richonline_selection(const std::filesystem::path& path) {
    json selected;
    {
        richnet::Storage store(path, richnet::ClientProfile::richonline);
        const auto role = store.dispatch("accounts.create", {{"username", "TraditionalOwner"},
            {"password", "model-test"}}).at("account");
        const auto id = role.at("role_id").get<std::int64_t>();
        for (std::uint32_t model = 0; model <= 8; ++model)
            check(store.select_model("TraditionalOwner", id, model).at("model") == model,
                  "all nine resource-backed richonline characters accepted");
        selected = store.select_model("TraditionalOwner", id, 8);
        auto expected = role;
        expected["model"] = 8;
        check(selected == expected, "richonline selection preserves all other profile fields");
        rejects([&] { store.select_model("OtherOwner", id, 2); }, "model_role_not_owned");
        rejects([&] { store.select_model("TraditionalOwner", id, 9); }, "model_selection_invalid");
        check(store.roles_for_username("TraditionalOwner").at(0) == selected,
              "richonline rejected selection preserves chosen model");
    }
    richnet::Storage reopened(path, richnet::ClientProfile::richonline);
    check(reopened.roles_for_username("TraditionalOwner").at(0) == selected,
          "richonline selection persists across reopen");
}
}
int main() {
    try {
        const auto base = std::filesystem::temp_directory_path() /
            ("model-storage-tests-" + std::to_string(GetCurrentProcessId()) + "-" +
             std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(base);
        const auto run = [&](std::string_view name, auto test) {
            test(base / (std::string(name) + ".sqlite3"));
            std::cout << "PASS " << name << '\n';
        };
        run("selection-audit-preserve-fields-and-reopen", success_and_reopen);
        run("repeated-selection-no-audit", repeated_selection);
        run("ownership-and-range-no-writes", ownership_and_range);
        run("audit-failure-rolls-back", audit_rollback);
        run("richonline-selection-ownership-range-and-reopen", richonline_selection);
        std::cout << "Isolated fixtures: " << base.string() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
