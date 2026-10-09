#include "storage.hpp"
#include "storage_detail.hpp"

#include <windows.h>
#include <array>
#include <chrono>
#include <functional>
#include <iostream>
#include <memory>
#include <string_view>

namespace {
using nlohmann::json;
using richnet::storage_detail::Statement;
void check(bool condition,std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}
void rejects(const std::function<void()>& action,std::string_view code) {
    try { action(); } catch (const richnet::StorageError& error) {
        check(error.what()==code,"unexpected preference rejection"); return;
    }
    throw std::runtime_error("expected preference rejection missing");
}
std::span<const std::uint8_t> bytes(std::string_view value) {
    return {reinterpret_cast<const std::uint8_t*>(value.data()),value.size()};
}
void save(richnet::Storage& storage,const std::string& value) {
    auto payload=value; payload.push_back('\0');
    storage.save_preferences("Player",bytes(payload));
}
}

int main() {
    try {
        const auto root=std::filesystem::absolute("preferences-test-"+std::to_string(GetCurrentProcessId())+"-"+
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        const auto path=root/"accounts.sqlite3";
        json role;
        {
            richnet::Storage storage(path,richnet::ClientProfile::original);
            role=storage.dispatch("accounts.create",{{"username","Player"},{"password","pw"}}).at("account");
            storage.dispatch("accounts.create",{{"username","Other"},{"password","other"}});
            check(!storage.preferences_for_username("Player"),"new account has no saved preferences");
            rejects([&] { storage.preferences_for_username("missing"); },"account_not_found");
            rejects([&] { storage.save_preferences("missing",bytes(std::string_view("4\0",2))); },"account_not_found");
            for (const auto& value:{std::string{},std::string(1,'\0'),std::string("14"),std::string("12345678901\0",12)})
                rejects([&] { storage.save_preferences("Player",bytes(value)); },"preference_length_or_terminator_invalid");
            for (const auto& value:{std::string("-1\0",3),std::string("+1\0",3),std::string(" 1\0",3),std::string("1.0\0",4),
                                   std::string("1\0\0",3),std::string("a\0",2),std::string("\xff\0",2)})
                rejects([&] { storage.save_preferences("Player",bytes(value)); },"preference_not_decimal");
            for (const auto& value:{"2147483648","4294967296","9999999999"})
                rejects([&] { save(storage,value); },"preference_out_of_range");
            save(storage,"0");
            check(storage.preferences_for_username("Player")=="0","minimum mask persisted");
            save(storage,"2147483647");
            check(storage.preferences_for_username("Player")=="2147483647","maximum mask retains high bits");
            save(storage,"0000004096");
            check(storage.preferences_for_username("Player")=="0000004096","validated decimal text retains leading zeros");
            save(storage,"0000004096");
            check(!storage.preferences_for_username("Other"),"saving preferences isolates other account");
            check(storage.roles_for_username("Player")==json::array({role}),"preference save preserves all role fields");
            check(storage.verify_credentials("Player",bytes("pw")),"preference save preserves credentials");
        }
        {
            richnet::Storage reopened(path,richnet::ClientProfile::original);
            check(reopened.preferences_for_username("Player")=="0000004096","preferences survive reopen");
            const auto encoded=path.u8string(); sqlite3* raw=nullptr;
            check(sqlite3_open_v2(reinterpret_cast<const char*>(encoded.c_str()),&raw,SQLITE_OPEN_READWRITE,nullptr)==SQLITE_OK,"open preference evidence");
            const std::unique_ptr<sqlite3,decltype(&sqlite3_close)> database(raw,sqlite3_close);
            Statement audit(raw,"SELECT old_value,new_value,source,reason,username FROM audit WHERE field='setting_text' ORDER BY id");
            const std::array<std::pair<std::string,std::string>,3> expected{{{"","0"},{"0","2147483647"},{"2147483647","0000004096"}}};
            for (const auto& [old_value,new_value]:expected) {
                check(audit.row(),"preference change audit missing");
                check(audit.text(0)==old_value && audit.text(1)==new_value && audit.text(2)=="lobby" &&
                      audit.text(3)=="client preferences" && audit.text(4)=="Player","preference audit values mismatch");
            }
            check(!audit.row(),"invalid/no-op/missing account preference saves must not audit");
            richnet::storage_detail::execute(raw,"CREATE TRIGGER reject_preference_audit BEFORE INSERT ON audit WHEN NEW.field='setting_text' BEGIN SELECT RAISE(ABORT,'test rollback'); END;");
            rejects([&] { save(reopened,"4097"); },"database_constraint_failed");
            check(reopened.preferences_for_username("Player")=="0000004096","failed audit rolls back preference mutation");
        }
        std::cout<<"PASS preference bounds, decimal validation, account isolation, raw text, high bits, audit/no-op, rollback, reopen.\n";
        std::cout<<"Isolated artifacts: "<<root.string()<<'\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr<<"FAIL "<<error.what()<<'\n'; return 1;
    }
}
