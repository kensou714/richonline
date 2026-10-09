#include "storage.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <chrono>
#include <functional>
#include <iostream>
#include <thread>

namespace {
void check(bool value,const char* reason) { if (!value) throw std::runtime_error(reason); }
void rejects(const std::function<void()>& action,const char* code) {
    try { action(); } catch (const richnet::StorageError& error) {
        check(std::string(error.what())==code,"unexpected storage rejection"); return;
    }
    throw std::runtime_error("expected storage rejection missing");
}
void sql(const std::filesystem::path& path,const char* command) {
    sqlite3* db=nullptr;
    const auto utf8=path.u8string();
    check(sqlite3_open(reinterpret_cast<const char*>(utf8.c_str()),&db)==SQLITE_OK,"fixture open");
    const int code=sqlite3_exec(db,command,nullptr,nullptr,nullptr);
    sqlite3_close(db); check(code==SQLITE_OK,"fixture mutation");
}
std::int64_t scalar(const std::filesystem::path& path,const char* command) {
    sqlite3* db=nullptr; sqlite3_stmt* statement=nullptr;
    const auto utf8=path.u8string();
    check(sqlite3_open_v2(reinterpret_cast<const char*>(utf8.c_str()),&db,SQLITE_OPEN_READONLY,nullptr)==SQLITE_OK,"fixture read");
    check(sqlite3_prepare_v2(db,command,-1,&statement,nullptr)==SQLITE_OK,"fixture prepare");
    check(sqlite3_step(statement)==SQLITE_ROW,"fixture scalar");
    const auto result=sqlite3_column_int64(statement,0);
    sqlite3_finalize(statement); sqlite3_close(db); return result;
}
std::int64_t account(richnet::Storage& store,const std::string& username) {
    return store.dispatch("accounts.create",{{"username",username},{"password","test-pass"}})
        .at("account").at("role_id").get<std::int64_t>();
}
constexpr std::int64_t now=1000;
constexpr std::int64_t expiry=2593000;

void grants_persist_without_changing_account(const std::filesystem::path& path) {
    nlohmann::json before;
    std::int64_t role{};
    {
        richnet::Storage store(path);
        role=account(store,"existing");
        before=store.roles_for_username("existing");
    }
    // Simulate a pre-feature v6 database; constructor adds only the two new tables.
    sql(path,"DROP TABLE lobby_equipment; DROP TABLE lobby_inventory; CREATE TABLE verifier_snapshot AS SELECT * FROM accounts;");
    {
        richnet::Storage store(path);
        const auto grant=store.ensure_test_rp_certificate("existing",now);
        check(grant.granted && !grant.renewed && grant.equipped==1 && grant.conflicts==0,"grant existing account");
    }
    richnet::Storage reopened(path);
    const auto inventory=reopened.lobby_inventory("existing",role,now);
    check(inventory.items==std::vector<std::uint32_t>{13} && inventory.equipment[13]==13,"persistent certificate and POCKET equipment");
    check(reopened.lobby_inventory_for_role(role,now).equipment==inventory.equipment,"host and lobby equipment agree");
    check(reopened.roles_for_username("existing")==before,"balances and role fields preserved");
    check(scalar(path,"SELECT count(*) FROM accounts a JOIN verifier_snapshot v ON a.username=v.username AND a.salt=v.salt AND a.password_hash=v.password_hash")==1,"credentials preserved");
    check(scalar(path,"SELECT count(*) FROM audit WHERE source='native-test-rp-policy' AND reason<>''")==2,"grant and equipment audited");
}

void active_grant_is_idempotent_and_expiry_renews(const std::filesystem::path& path) {
    richnet::Storage store(path);
    const auto role=account(store,"expiry");
    store.ensure_test_rp_certificate("expiry",now);
    const auto repeated=store.ensure_test_rp_certificate("expiry",now+10);
    check(!repeated.granted && !repeated.renewed && repeated.equipped==0,"repeat grant is no-op");
    check(scalar(path,"SELECT expires_at FROM lobby_inventory")==expiry,"active grant does not extend expiry");
    check(store.lobby_inventory("expiry",role,expiry-1).equipment[13]==13,"active until expiry");
    const auto expired=store.lobby_inventory("expiry",role,expiry);
    check(expired.items.empty() && expired.equipment[13]==0,"expiry removes item and effective equipment");
    check(store.lobby_inventory_for_role(role,expiry).equipment[13]==0,"host also filters expiry");
    const auto renewed=store.ensure_test_rp_certificate("expiry",expiry);
    check(renewed.renewed && !renewed.granted && renewed.equipped==0,"expired grant renewed without duplicate equipment");
    check(scalar(path,"SELECT count(*) FROM lobby_inventory")==1,"one owned certificate after renewal");
    check(scalar(path,"SELECT count(*) FROM audit WHERE source='native-test-rp-policy'")==3,"idempotent call emits no duplicate audits");
}

void conflicts_and_cas_preserve_ownership(const std::filesystem::path& path) {
    richnet::Storage store(path);
    const auto role=account(store,"owner");
    const auto stranger=account(store,"stranger");
    rejects([&]{store.ensure_test_rp_certificate("missing",now);},"lobby_inventory_account_has_no_roles");
    rejects([&]{store.ensure_test_rp_certificate("owner",-1);},"lobby_inventory_time_invalid");
    rejects([&]{store.lobby_inventory_for_role(2147483647,now);},"lobby_inventory_role_missing");
    rejects([&]{store.update_lobby_equipment("owner",{role,32,0,13},now);},"lobby_equipment_slot_invalid");
    sql(path,"INSERT INTO lobby_inventory VALUES('owner',14,0); INSERT INTO lobby_equipment SELECT role_id,13,14 FROM roles WHERE username='owner';");
    const auto grant=store.ensure_test_rp_certificate("owner",now);
    check(grant.granted && grant.equipped==0 && grant.conflicts==1,"existing POCKET item preserved");
    check(store.lobby_inventory("owner",role,now).equipment[13]==14,"conflict retains item");
    rejects([&]{store.lobby_inventory("stranger",role,now);},"lobby_inventory_role_not_owned");
    rejects([&]{store.update_lobby_equipment("stranger",{role,13,14,13},now);},"lobby_inventory_role_not_owned");
    rejects([&]{store.update_lobby_equipment("stranger",{stranger,13,0,13},now);},"lobby_equipment_item_not_owned_or_expired");
    rejects([&]{store.update_lobby_equipment("owner",{role,13,0,13},now);},"lobby_equipment_stale");
    rejects([&]{store.update_lobby_equipment("owner",{role,13,14,0x200d},now);},"lobby_equipment_item_not_owned_or_expired");
    store.update_lobby_equipment("owner",{role,13,14,13},now);
    check(store.lobby_inventory("owner",role,now).equipment[13]==13,"owned CAS update applied");
    rejects([&]{store.update_lobby_equipment("owner",{role,13,13,13},expiry);},"lobby_equipment_item_not_owned_or_expired");
    store.update_lobby_equipment("owner",{role,13,13,0},expiry);
    check(store.lobby_inventory("owner",role,expiry).equipment[13]==0,"expired equipment can be removed");
}

void independent_connections_do_not_duplicate_grant(const std::filesystem::path& path) {
    richnet::Storage first(path);
    account(first,"concurrent");
    richnet::Storage second(path);
    std::exception_ptr a,b;
    std::thread one([&]{try {first.ensure_test_rp_certificate("concurrent",now);} catch (...) {a=std::current_exception();}});
    std::thread two([&]{try {second.ensure_test_rp_certificate("concurrent",now);} catch (...) {b=std::current_exception();}});
    one.join(); two.join();
    if (a) std::rethrow_exception(a);
    if (b) std::rethrow_exception(b);
    check(scalar(path,"SELECT count(*) FROM lobby_inventory")==1,"concurrent grant unique");
    check(scalar(path,"SELECT count(*) FROM audit WHERE source='native-test-rp-policy'")==2,"concurrent grant audits unique");
}

void original_profile_is_unchanged(const std::filesystem::path& path) {
    richnet::Storage store(path,richnet::ClientProfile::original);
    account(store,"original");
    rejects([&]{store.ensure_test_rp_certificate("original",now);},"lobby_inventory_profile_unsupported");
    check(scalar(path,"SELECT count(*) FROM sqlite_master WHERE name IN ('lobby_inventory','lobby_equipment')")==0,"original schema unchanged");
}
}

int main() {
    try {
        const auto base=std::filesystem::absolute("lobby-inventory-test-"+std::to_string(GetCurrentProcessId())+"-"+
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(base);
        grants_persist_without_changing_account(base/"preserved.sqlite3");
        active_grant_is_idempotent_and_expiry_renews(base/"expiry.sqlite3");
        conflicts_and_cas_preserve_ownership(base/"ownership.sqlite3");
        independent_connections_do_not_duplicate_grant(base/"concurrent.sqlite3");
        original_profile_is_unchanged(base/"original.sqlite3");
        std::filesystem::remove_all(base);
        std::cout<<"lobby inventory tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr<<"lobby inventory tests failed: "<<error.what()<<'\n'; return 1;
    }
}
