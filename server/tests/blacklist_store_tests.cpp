#include "blacklist_store.hpp"

#include <sqlite3.h>
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <exception>
#include <functional>
#include <iostream>
#include <memory>
#include <string_view>
#include <thread>

namespace {
using Bytes=std::vector<std::uint8_t>;
using richnet::BlacklistStore;
void check(bool value, std::string_view message) {
    if (!value) throw std::runtime_error(std::string(message));
}
Bytes bytes(std::string_view text) { return {text.begin(),text.end()}; }
std::vector<richnet::BlacklistEntry> entries(const Bytes& target, bool enabled=true) {
    return {{target,enabled}};
}
void rejects(const std::function<void()>& action) {
    try { action(); } catch (const richnet::BlacklistStoreError&) { return; }
    throw std::runtime_error("expected blacklist rejection");
}
void sql(sqlite3* db, const char* statement) {
    check(sqlite3_exec(db,statement,nullptr,nullptr,nullptr)==SQLITE_OK,"test database operation failed");
}
}

int main() {
    try {
        const auto root=std::filesystem::absolute("blacklist-test-"+std::to_string(GetCurrentProcessId())+"-"+
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        const auto path=root/"original-blacklist.sqlite3";
        const auto owner=bytes("Owner"), other=bytes("owner");
        const auto digest=bytes("0123456789abcdef0123456789abcdef"), different=bytes("abcdef0123456789abcdef0123456789");
        const Bytes target{0xb2,0xe2,0xca,0xd4};
        const Bytes full_name(32,0xfe);
        {
            BlacklistStore store(path);
            check(store.list(owner,digest).empty(),"new blacklist empty");
            store.add(owner,digest,target); store.add(owner,digest,target);
            check(store.list(owner,digest)==entries(target),"duplicate add idempotent and bytes preserved");
            store.add(other,digest,bytes("other-target"));
            store.add(owner,different,bytes("digest-target"));
            check(store.list(owner,digest)==entries(target),"owner and digest isolation");
            store.add(full_name,digest,full_name);
            check(store.list(full_name,digest)==entries(full_name),"full 32 byte owner and target preserved");
            check(!store.remove(owner,digest,bytes("absent")),"nonexistent delete false");
            check(store.remove(other,digest,bytes("other-target")),"existing delete true");
            check(!store.remove(other,digest,bytes("other-target")),"repeat delete false");
            for (const auto& invalid:{Bytes{},Bytes(33,'x'),Bytes{'a',0,'b'}}) {
                rejects([&] { store.list(invalid,digest); });
                rejects([&] { store.add(owner,digest,invalid); });
                rejects([&] { store.remove(owner,digest,invalid); });
                rejects([&] { store.set_enabled(owner,digest,invalid,false); });
            }
            for (const auto& invalid:{Bytes{},Bytes(31,'a'),Bytes(33,'a'),Bytes(32,'A'),Bytes(32,'g'),Bytes(32,0)}) {
                rejects([&] { store.list(owner,invalid); });
                rejects([&] { store.add(owner,invalid,target); });
                rejects([&] { store.remove(owner,invalid,target); });
                rejects([&] { store.set_enabled(owner,invalid,target,false); });
            }
            sqlite3* raw=nullptr; const auto encoded=path.u8string();
            check(sqlite3_open_v2(reinterpret_cast<const char*>(encoded.c_str()),&raw,SQLITE_OPEN_READWRITE,nullptr)==SQLITE_OK,"open evidence database");
            const std::unique_ptr<sqlite3,decltype(&sqlite3_close)> evidence(raw,sqlite3_close);
            sql(raw,"CREATE TRIGGER reject_add AFTER INSERT ON blacklist BEGIN SELECT RAISE(ABORT,'injected failure'); END");
            rejects([&] { store.add(owner,digest,bytes("rollback")); });
            check(store.list(owner,digest)==entries(target),"failed insert atomic rollback");
            sql(raw,"DROP TRIGGER reject_add");
            sql(raw,"CREATE TRIGGER reject_remove AFTER DELETE ON blacklist BEGIN SELECT RAISE(ABORT,'injected failure'); END");
            rejects([&] { store.remove(owner,digest,target); });
            check(store.list(owner,digest)==entries(target),"failed delete atomic rollback");
            sql(raw,"DROP TRIGGER reject_remove");
            check(!store.set_enabled(owner,digest,bytes("absent"),false),"missing target toggle false");
            check(store.set_enabled(owner,digest,target,false),"existing target disable true");
            check(store.set_enabled(owner,digest,target,false),"same value target disable true");
            store.add(owner,digest,target);
            check(store.list(owner,digest)==entries(target,false),"duplicate add preserves disabled state");
            check(store.list(owner,different)==entries(bytes("digest-target")),"toggle isolates digest");
            check(store.list(full_name,digest)==entries(full_name),"toggle isolates owner");
            store.add(owner,digest,bytes("another"));
            const auto separated=store.list(owner,digest);
            check(separated.size()==2 && separated[0]==richnet::BlacklistEntry{bytes("another"),true} &&
                  separated[1]==richnet::BlacklistEntry{target,false},"toggle isolates target");
            check(store.remove(owner,digest,bytes("another")),"remove additional target");
            sql(raw,"CREATE TRIGGER reject_toggle AFTER UPDATE ON blacklist BEGIN SELECT RAISE(ABORT,'injected failure'); END");
            rejects([&] { store.set_enabled(owner,digest,target,true); });
            check(store.list(owner,digest)==entries(target,false),"failed toggle atomic rollback");
            sql(raw,"DROP TRIGGER reject_toggle");
        }
        {
            BlacklistStore first(path), second(path);
            check(first.list(owner,digest)==entries(target,false),"reopen preserves disabled and rollback state");
            check(first.list(owner,different)==entries(bytes("digest-target")),"reopen digest isolation");
            check(first.list(full_name,digest)==entries(full_name),"reopen binary full name");
            check(first.list(other,digest).empty(),"delete persisted");
            std::exception_ptr failure_a, failure_b;
            auto write=[&](BlacklistStore& store,std::exception_ptr& failure) {
                try { for (int i=0;i<100;++i) store.add(other,digest,bytes("concurrent-"+std::to_string(i))); }
                catch (...) { failure=std::current_exception(); }
            };
            std::thread a(write,std::ref(first),std::ref(failure_a));
            std::thread b(write,std::ref(second),std::ref(failure_b));
            a.join(); b.join();
            if (failure_a) std::rethrow_exception(failure_a);
            if (failure_b) std::rethrow_exception(failure_b);
            const auto rows=first.list(other,digest);
            check(rows.size()==100 && rows==second.list(other,digest),"concurrent independent stores consistent and duplicate free");
            check(std::is_sorted(rows.begin(),rows.end(),[](const auto& a,const auto& b) { return a.target<b.target; }),"stable binary target order");
        }
        const auto legacy_path=root/"legacy-blacklist.sqlite3";
        {
            sqlite3* raw=nullptr; const auto encoded=legacy_path.u8string();
            check(sqlite3_open_v2(reinterpret_cast<const char*>(encoded.c_str()),&raw,SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE,nullptr)==SQLITE_OK,"open legacy database");
            const std::unique_ptr<sqlite3,decltype(&sqlite3_close)> evidence(raw,sqlite3_close);
            sql(raw,"CREATE TABLE blacklist(owner BLOB NOT NULL,digest BLOB NOT NULL,target BLOB NOT NULL,PRIMARY KEY(owner,digest,target)) WITHOUT ROWID");
            sql(raw,"INSERT INTO blacklist VALUES(x'4f776e6572',CAST('0123456789abcdef0123456789abcdef' AS BLOB),x'b2e2cad4')");
        }
        {
            BlacklistStore migrated(legacy_path);
            check(migrated.list(owner,digest)==entries(target),"additive migration preserves record with enabled default");
            check(migrated.set_enabled(owner,digest,target,false),"migrated flag can be updated");
        }
        {
            BlacklistStore migrated(legacy_path);
            check(migrated.list(owner,digest)==entries(target,false),"migration is idempotent and preserves updated flag");
        }
        std::cout<<"PASS blacklist binary identities, digest isolation, validation, idempotence, removal, flags, migration, rollback, persistence, concurrent handles.\n";
        std::cout<<"Isolated artifacts: "<<root.string()<<'\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr<<"FAIL "<<error.what()<<'\n'; return 1;
    }
}
