#include "richonline_npc.hpp"
#include "sqlite3.h"
#include <filesystem>
#include <iostream>

namespace {
using namespace richnet;
void check(bool ok,const char* reason) { if(!ok) throw std::runtime_error(reason); }
struct Database {
    sqlite3* db=nullptr;
    std::filesystem::path path;
    Database() : path(std::filesystem::temp_directory_path()/
        ("richonline-npc-atomic-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())+".db")) {
        std::filesystem::create_directories(path.parent_path());
        const auto utf8=path.u8string();
        check(sqlite3_open(reinterpret_cast<const char*>(utf8.c_str()),&db)==SQLITE_OK,"sqlite_open_failed");
        exec("CREATE TABLE game_funds(actor INTEGER PRIMARY KEY,cash INTEGER NOT NULL,deposit INTEGER NOT NULL,revision INTEGER NOT NULL);"
             "INSERT INTO game_funds VALUES(0,100,1000,0),(1,40,100,0);");
    }
    ~Database() { if(db) sqlite3_close(db); std::error_code error; std::filesystem::remove(path,error); }
    void exec(const char* sql) { check(sqlite3_exec(db,sql,nullptr,nullptr,nullptr)==SQLITE_OK,"sqlite_statement_failed"); }
    std::array<std::int64_t,3> row(int actor) {
        sqlite3_stmt* stmt=nullptr;
        check(sqlite3_prepare_v2(db,"SELECT cash,deposit,revision FROM game_funds WHERE actor=?",-1,&stmt,nullptr)==SQLITE_OK,"sqlite_read_prepare_failed");
        sqlite3_bind_int(stmt,1,actor); const auto stepped=sqlite3_step(stmt);
        std::array<std::int64_t,3> result{};
        if(stepped==SQLITE_ROW) for(int i=0;i<3;++i) result[static_cast<std::size_t>(i)]=sqlite3_column_int64(stmt,i);
        sqlite3_finalize(stmt); check(stepped==SQLITE_ROW,"sqlite_row_missing"); return result;
    }
    // Test transaction adapter. Production schema/persistence remains root-owned.
    bool transaction(const RichonlineDeityMoneyPlan& plan,bool decline=false,bool inject_error=false) {
        exec("BEGIN IMMEDIATE");
        try {
            for(std::size_t i=0;i<2;++i) {
                sqlite3_stmt* stmt=nullptr;
                check(sqlite3_prepare_v2(db,"UPDATE game_funds SET cash=?,deposit=?,revision=revision+1 WHERE actor=? AND cash=? AND deposit=? AND revision=?",-1,&stmt,nullptr)==SQLITE_OK,"sqlite_update_prepare_failed");
                sqlite3_bind_int64(stmt,1,plan.after[i].cash);
                sqlite3_bind_int64(stmt,2,*plan.after[i].deposit);
                sqlite3_bind_int64(stmt,3,static_cast<sqlite3_int64>(i));
                sqlite3_bind_int64(stmt,4,plan.before[i].funds.cash);
                sqlite3_bind_int64(stmt,5,*plan.before[i].funds.deposit);
                sqlite3_bind_int64(stmt,6,static_cast<sqlite3_int64>(plan.before[i].revision));
                const auto status=sqlite3_step(stmt); sqlite3_finalize(stmt);
                check(status==SQLITE_DONE && sqlite3_changes(db)==1,"sqlite_snapshot_conflict");
                if(i==0 && inject_error) exec("INSERT INTO missing_table VALUES(1)");
            }
            if(decline) { exec("ROLLBACK"); return false; }
            exec("COMMIT"); return true;
        } catch(...) { sqlite3_exec(db,"ROLLBACK",nullptr,nullptr,nullptr); throw; }
    }
};
RichonlineDeityMoneyPlan plan(RichonlineGameLedger& ledger) {
    RichonlineActorStatus status; status.possession=0;
    return plan_richonline_deity_money({0x1234,0,RichonlineDeityMoneyOrigin::ground,{10,20}},70,status,
        {ledger.snapshot(0),ledger.snapshot(1)});
}
template<class F> void rejects(F fn) { try { fn(); } catch(const std::exception&) { return; } throw std::runtime_error("expected_rejection_missing"); }
void transactions() {
    for(const auto mode:{0,1,2}) {
        Database db;
        RichonlineGameLedger ledger({{100,1000,7,99},{40,100,8,88}});
        const auto planned=plan(ledger);
        if(mode==2) rejects([&] { commit_richonline_deity_money(ledger,planned,[&] { return db.transaction(planned,false,true); }); });
        else check(commit_richonline_deity_money(ledger,planned,[&] { return db.transaction(planned,mode==1); })==(mode==0),"authorization_result_wrong");
        if(mode==0) {
            check(ledger.snapshot(0).funds==planned.after[0] && ledger.snapshot(1).funds==planned.after[1] &&
                ledger.snapshot(0).revision==1 && ledger.snapshot(1).revision==1,"ledger_commit_incomplete");
            check(db.row(0)==std::array<std::int64_t,3>{170,1000,1} && db.row(1)==std::array<std::int64_t,3>{0,70,1},"sqlite_commit_incomplete");
            bool called=false;
            rejects([&] { commit_richonline_deity_money(ledger,planned,[&] { called=true; return true; }); });
            check(!called && db.row(1)==std::array<std::int64_t,3>{0,70,1},"duplicate_plan_replayed");
        } else {
            check(ledger.snapshot(0)==planned.before[0] && ledger.snapshot(1)==planned.before[1],"failed_db_transaction_partially_mutated_ledger");
            check(db.row(0)==std::array<std::int64_t,3>{100,1000,0} && db.row(1)==std::array<std::int64_t,3>{40,100,0},"db_rollback_failed");
        }
    }
    Database db;
    RichonlineGameLedger ledger({{100,1000,7,99},{40,100,8,88}});
    const auto planned=plan(ledger);
    ledger.adjust(1,ledger.snapshot(1),{1,0,0,0});
    bool called=false;
    rejects([&] { commit_richonline_deity_money(ledger,planned,[&] { called=true; return db.transaction(planned); }); });
    check(!called && ledger.snapshot(0)==planned.before[0] && ledger.snapshot(1).funds.cash==41 &&
        db.row(0)==std::array<std::int64_t,3>{100,1000,0},"stale_second_actor_debited_first_actor");
    const auto fresh=plan(ledger);
    rejects([&] { commit_richonline_deity_money(ledger,fresh,[&] { return db.transaction(fresh); }); });
    check(ledger.snapshot(0)==fresh.before[0] && ledger.snapshot(1)==fresh.before[1] &&
        db.row(0)==std::array<std::int64_t,3>{100,1000,0},"db_second_actor_conflict_did_not_rollback_first");
    const auto snapshot=ledger.snapshot(0);
    const std::array<RichonlineGameFundsUpdate,2> duplicate{{{0,snapshot,snapshot.funds},{0,snapshot,snapshot.funds}}};
    rejects([&] { ledger.commit_batch(duplicate,[]{ return true; }); });
}
}
int main() { try { transactions(); std::cout<<"PASS NEW NPC real SQLite and ledger atomic multi-actor commit/rollback/CAS\n"; }
    catch(const std::exception& e) { std::cerr<<"FAIL "<<e.what()<<'\n'; return 1; } }
