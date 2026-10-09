#include "storage.hpp"
#include "credentials.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <chrono>
#include <functional>
#include <iostream>
#include <string_view>

namespace {
using nlohmann::json;
void check(bool condition,std::string_view name) {
    if (!condition) throw std::runtime_error(std::string(name));
}
void rejects(const std::function<void()>& action,std::string_view code) {
    try { action(); } catch (const std::runtime_error& e) {
        check(e.what()==code,"wrong rejection code"); return;
    }
    throw std::runtime_error("expected rejection missing");
}
std::span<const std::uint8_t> bytes(std::string_view value) {
    return {reinterpret_cast<const std::uint8_t*>(value.data()),value.size()};
}
std::string hex(std::span<const std::uint8_t> value) {
    const char* digits="0123456789abcdef";
    std::string output;
    for (auto b:value) { output+=digits[b>>4]; output+=digits[b&15]; }
    return output;
}
void sql(const std::filesystem::path& path,const char* command) {
    sqlite3* db=nullptr;
    const auto utf8=path.u8string();
    check(sqlite3_open(reinterpret_cast<const char*>(utf8.c_str()),&db)==SQLITE_OK,"open test fixture");
    const int result=sqlite3_exec(db,command,nullptr,nullptr,nullptr);
    sqlite3_close(db);
    check(result==SQLITE_OK,"write test fixture");
}
std::int64_t scalar(const std::filesystem::path& path,const char* command) {
    sqlite3* db=nullptr; sqlite3_stmt* statement=nullptr;
    const auto utf8=path.u8string();
    check(sqlite3_open_v2(reinterpret_cast<const char*>(utf8.c_str()),&db,SQLITE_OPEN_READONLY,nullptr)==SQLITE_OK,"read test fixture");
    check(sqlite3_prepare_v2(db,command,-1,&statement,nullptr)==SQLITE_OK,"prepare fixture query");
    check(sqlite3_step(statement)==SQLITE_ROW,"fixture row");
    const auto result=sqlite3_column_int64(statement,0);
    sqlite3_finalize(statement); sqlite3_close(db);
    return result;
}
}

int main() {
    try {
        check(hex(richnet::scrypt(bytes(""),bytes(""),16,1,1,64))==
              "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
              "RFC7914 empty vector");
        check(hex(richnet::scrypt(bytes("pleaseletmein"),bytes("SodiumChloride"),16384,8,1,64))==
              "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
              "RFC7914 legacy parameters vector");
        check(hex(richnet::scrypt(bytes("password"),bytes("NaCl"),1024,8,16,64))==
              "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
              "RFC7914 parallel blocks vector");
        check(richnet::client_text("測試").size()==4,"Big5 Chinese text conversion");
        const auto base=std::filesystem::absolute("storage-test-"+std::to_string(GetCurrentProcessId())+"-"+
                          std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(base);
        using Profile=richnet::ClientProfile;
        check(hex(richnet::client_text("中文",Profile::original))=="d6d0cec4","original CP936 bytes");
        check(hex(richnet::client_text("中文"))=="a4a4a4e5","default CP950 bytes retained");
        rejects([] { richnet::client_text("😀",Profile::original); },"client_text_not_gbk");
        rejects([] { richnet::parse_client_profile("guess"); },"client_profile_invalid");
        {
            richnet::Storage traditional(base/"traditional.sqlite3");
            traditional.dispatch("accounts.create",{{"username","測試"},{"password","中文"}});
            check(traditional.verify_credentials("測試",bytes("\xa4\xa4\xa4\xe5")),"default Big5 Chinese password remains compatible");
            check(!traditional.verify_credentials("測試",bytes("\xd6\xd0\xce\xc4")),"GBK password bytes rejected for Big5 account");
        }
        const auto original_path=base/"original.sqlite3";
        json original_role;
        {
            richnet::Storage original(original_path,Profile::original);
            original_role=original.dispatch("accounts.create",{{"username","测试账户"},{"password","中文"}}).at("account");
            check(original.verify_credentials("测试账户",bytes("\xd6\xd0\xce\xc4")),"GBK password authenticates raw original bytes");
            check(!original.verify_credentials("测试账户",bytes("\xa4\xa4\xa4\xe5")),"Big5 password bytes rejected for original account");
            original_role=original.dispatch("accounts.update",{{"role_id",original_role.at("role_id")},{"expected",original_role},
                {"changes",{{"name","简体角色"}}},{"reason","GBK role rename"}}).at("account");
            check(original_role.at("name")=="简体角色","GBK role name accepted");
            rejects([&] { original.dispatch("accounts.update",{{"role_id",original_role.at("role_id")},{"expected",original_role},
                {"changes",{{"name","中文中文中文中文中文中文中文中文"}}},{"reason","long role name"}}); },"role_name_invalid");
        }
        {
            richnet::Storage reopened(original_path,Profile::original);
            check(reopened.verify_credentials("测试账户",bytes("\xd6\xd0\xce\xc4")),"GBK credentials survive reopen");
            check(reopened.dispatch("accounts.list",json::object()).at("accounts").at(0)==original_role,"original role survives reopen");
        }
        rejects([&] { richnet::Storage wrong(original_path); },"database_client_profile_mismatch");
        rejects([&] { richnet::Storage wrong(original_path,Profile::richonline,true); },"database_client_profile_mismatch");
        sql(original_path,"DELETE FROM metadata WHERE key='client_profile'; CREATE TABLE preserved_verifiers AS SELECT username,salt,password_hash FROM accounts;");
        const auto legacy_path=base/"legacy-original.sqlite3";
        richnet::Storage::import_database(original_path,legacy_path);
        rejects([&] { richnet::Storage legacy(legacy_path); },"database_client_profile_adoption_required");
        rejects([&] { richnet::Storage legacy(legacy_path,Profile::original); },"database_client_profile_adoption_required");
        check(scalar(legacy_path,"SELECT count(*) FROM metadata WHERE key='client_profile'")==0,"failed legacy open must not tag profile");
        {
            richnet::Storage adopted(legacy_path,Profile::original,true);
            check(adopted.verify_credentials("测试账户",bytes("\xd6\xd0\xce\xc4")),"explicit original legacy adoption preserves authentication");
            check(adopted.dispatch("accounts.list",json::object()).at("accounts").at(0)==original_role,"legacy adoption preserves role");
        }
        check(scalar(legacy_path,"SELECT count(*) FROM accounts a JOIN preserved_verifiers p ON a.username=p.username AND a.salt=p.salt AND a.password_hash=p.password_hash")==1,"adoption must not reset or rehash credentials");
        check(scalar(original_path,"SELECT count(*) FROM metadata WHERE key='client_profile'")==0,"import leaves source untagged");
        rejects([&] { richnet::Storage wrong(legacy_path); },"database_client_profile_mismatch");
        const auto path=base/"source.sqlite3";
        json first,updated,configuration;
        std::filesystem::path backup_path;
        {
            richnet::Storage store(path);
            first=store.dispatch("accounts.create",{{"username","TestAccount"},{"password","test-pass"}}).at("account");
            check(first.at("level")==6 && first.at("coins")==10000.0,"test account defaults");
            check(store.verify_credentials("TestAccount",bytes("test-pass")),"generated scrypt authentication");
            check(!store.verify_credentials("TestAccount",bytes("wrong")),"wrong password rejection");
            check(store.dispatch("accounts.list",json::object()).at("accounts").at(0)==first,"public account listing");
            check(store.roles_for_username("TestAccount")==json::array({first}),"account-scoped role query");
            check(store.roles_for_username("missing-account").empty(),"missing account has no roles");
            rejects([&] { store.dispatch("accounts.create",{{"username","TestAccount"},{"password","other"}}); },"account_exists");
            updated=store.dispatch("accounts.update",{{"role_id",first.at("role_id")},{"expected",first},
                {"changes",{{"coins",12345.625},{"gold",64.25}}},{"reason","fractional balance test"}}).at("account");
            check(updated.at("coins")==12345.625 && updated.at("gold")==64.25,"REAL balance retained");
            rejects([&] { store.dispatch("accounts.update",{{"role_id",first.at("role_id")},{"expected",first},
                {"changes",{{"coins",99.0}}},{"reason","stale edit"}}); },"role_changed_refresh_required");
            rejects([&] { store.dispatch("accounts.update",{{"role_id",first.at("role_id")},{"expected",updated},
                {"changes",{{"coins",-1.0}}},{"reason","invalid edit"}}); },"role_balance_out_of_range");
            configuration=store.dispatch("config.get",json::object());
            auto settings=configuration.at("settings"); settings["announcement"]="integration test";
            configuration=store.dispatch("config.update",{{"expectedRevision",configuration.at("revision")},{"settings",settings}});
            rejects([&] { store.dispatch("config.update",{{"expectedRevision",1},{"settings",settings}}); },"settings_changed_refresh_required");
            const auto backup_text=store.dispatch("database.backup",json::object()).at("path").get<std::string>();
            backup_path=std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(backup_text.data()),backup_text.size()));
            check(backup_path.parent_path()==base/"backups","backup constrained path");
        }
        rejects([&] { richnet::Storage wrong(path,Profile::original); },"database_client_profile_mismatch");
        check(scalar(path,"SELECT count(*) FROM audit")==4,"creation two-field edit config audit count");
        {
            richnet::Storage reopened(path);
            check(reopened.dispatch("accounts.list",json::object()).at("accounts").at(0)==updated,"persistence after reopen");
            check(reopened.dispatch("config.get",json::object())==configuration,"configuration revision persistence");
            richnet::Storage backup(backup_path);
            check(backup.dispatch("accounts.list",json::object()).at("accounts").at(0)==updated,"backup snapshot");
            richnet::Storage other_writer(path);
            updated=other_writer.dispatch("accounts.update",{{"role_id",first.at("role_id")},{"expected",updated},
                {"changes",{{"bank",7.125}}},{"reason","second connection write"}}).at("account");
            rejects([&] { reopened.dispatch("accounts.update",{{"role_id",first.at("role_id")},
                {"expected",{{"bank",0.0}}},{"changes",{{"bank",8.0}}},{"reason","cross connection stale"}}); },
                "role_changed_refresh_required");
        }
        sql(path,"CREATE TABLE retained_extension(id INTEGER PRIMARY KEY,data BLOB); INSERT INTO retained_extension VALUES(8,x'00FE12'); DROP TABLE native_settings;");
        const auto imported_path=base/"imported.sqlite3";
        check(richnet::Storage::import_database(path,imported_path)==imported_path,"import destination");
        rejects([&] { richnet::Storage::import_database(path,imported_path); },"backup_target_exists_or_unavailable");
        check(scalar(imported_path,"SELECT count(*) FROM retained_extension WHERE id=8 AND data=x'00FE12'")==1,"unknown table preserved");
        {
            richnet::Storage imported(imported_path);
            check(imported.verify_credentials("TestAccount",bytes("test-pass")),"imported hash preserved");
            check(imported.dispatch("accounts.list",json::object()).at("accounts").at(0)==updated,"imported IDs and REAL preserved");
        }
        std::cout<<"PASS RFC7914 vectors; create/list/authenticate/CAS/audit/reopen/config/backup/import.\n";
        std::cout<<"Isolated fixtures: "<<base.string()<<'\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr<<"FAIL "<<error.what()<<'\n'; return 1;
    }
}
