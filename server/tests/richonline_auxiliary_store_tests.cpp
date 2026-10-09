#include "richonline_auxiliary_store.hpp"
#include "storage_detail.hpp"
#include <windows.h>
#include <chrono>
#include <iostream>

namespace {
using namespace richnet;
void check(bool yes, const char* reason) { if (!yes) throw std::runtime_error(reason); }
template<class Action> void rejects(Action action, const char* reason) {
    try { action(); } catch (const std::runtime_error& error) {
        check(std::string(error.what()) == reason, "wrong rejection"); return;
    }
    throw std::runtime_error("missing rejection");
}
Bytes request(const RichonlineAuxiliaryName& name) {
    Bytes result{13,10}; append_le(result,0,4); append_le(result,32,4);
    result.insert(result.end(),name.begin(),name.end()); return result;
}
}
int main() {
    try {
        const auto root = std::filesystem::absolute("intro-test-"+std::to_string(GetCurrentProcessId())+"-"+
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        const auto path = root/"accounts.sqlite3";
        Storage accounts(path);
        const auto player = accounts.dispatch("accounts.create",{{"username","Player"},{"password","test"}}).at("account");
        accounts.dispatch("accounts.create",{{"username","Other"},{"password","test-other"}});
        const auto id = player.at("role_id").get<std::int64_t>();
        const auto name = richonline_auxiliary_name("Player");
        {
            RichonlineAuxiliaryStore store(path);
            check(store.introduction(name).revision == 0, "default intro revision");
            const auto packet = request(name);
            for (std::size_t size=0; size<packet.size(); ++size)
                check(!store.intro_response(View(packet).first(size)), "partial intro dispatched");
            const auto empty = store.intro_response(packet);
            check(empty && empty->size() == 40, "known empty intro response");
            const auto saved = store.save_introduction("Player",id,"Hello",0,"administrator set introduction");
            check(saved.revision == 1 && saved.text_utf8 == "Hello", "save intro");
            check(store.save_introduction("Player",id,"Hello",1,"no op").revision == 1,"no op revision");
            const auto full = store.intro_response(packet);
            check(full && full->size() == 45 && (*full)[40] == 'H',"persisted text wire response");
            const std::string chinese_name = "測試角色";
            accounts.dispatch("accounts.update",{{"role_id",id},{"expected",{{"name","Player"}}},
                {"changes",{{"name",chinese_name}}},{"reason","intro rename boundary"}});
            const auto chinese_bytes = client_text(chinese_name);
            RichonlineAuxiliaryName chinese_wire{};
            std::copy(chinese_bytes.begin(),chinese_bytes.end(),chinese_wire.begin());
            check(store.introduction(chinese_wire).text_utf8=="Hello","renamed role lost intro");
            rejects([&]{store.introduction(name);},"intro_role_not_found");
            accounts.dispatch("accounts.update",{{"role_id",id},{"expected",{{"name",chinese_name}}},
                {"changes",{{"name","Player"}}},{"reason","restore test name"}});
            rejects([&]{store.save_introduction("Other",id,"wrong",1,"test");},"intro_role_not_owned");
            rejects([&]{store.save_introduction("Player",id,"wrong",0,"test");},"intro_changed_refresh_required");
            rejects([&]{store.introduction(richonline_auxiliary_name("missing"));},"intro_role_not_found");
            rejects([&]{store.save_introduction("Player",id,std::string(401,'x'),1,"test");},"richonline_intro_text_too_long");
            check(accounts.roles_for_username("Player")[0] == player,"intro changed role balances");
        }
        {
            RichonlineAuxiliaryStore reopened(path);
            check(reopened.introduction(name).text_utf8 == "Hello","intro lost on reopen");
            const auto encoded = path.u8string(); sqlite3* db = nullptr;
            check(sqlite3_open_v2(reinterpret_cast<const char*>(encoded.c_str()),&db,SQLITE_OPEN_READWRITE,nullptr)==SQLITE_OK,"audit open");
            {
                storage_detail::Statement query(db,"SELECT count(*) FROM audit WHERE field='introduction'");
                check(query.row() && query.integer(0)==1,"intro audit count");
            }
            storage_detail::execute(db,"CREATE TRIGGER reject_intro_audit BEFORE INSERT ON audit WHEN NEW.field='introduction' BEGIN SELECT RAISE(ABORT,'test rollback'); END;");
            rejects([&]{reopened.save_introduction("Player",id,"Rollback",1,"test");},"database_constraint_failed");
            check(reopened.introduction(name).text_utf8=="Hello" && reopened.introduction(name).revision==1,"audit rollback");
            sqlite3_close(db);
        }
        const auto old_path=root/"original.sqlite3";
        Storage old(old_path,ClientProfile::original);
        rejects([&]{RichonlineAuxiliaryStore bad(old_path);},"auxiliary_database_profile_mismatch");
        rejects([&]{RichonlineAuxiliaryStore bad(root/"absent.sqlite3");},"auxiliary_database_open_failed");
        check(!std::filesystem::exists(root/"absent.sqlite3"),"auxiliary created missing account db");
        std::cout << "PASS intro real role lookup, wire reply, ownership, CAS, persistence, audit rollback, profile isolation\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what()<<'\n'; return 1; }
}
