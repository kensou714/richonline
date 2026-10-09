#include "storage.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <chrono>
#include <future>
#include <iostream>
#include <memory>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
class Database {
public:
    explicit Database(const std::filesystem::path& path){const auto name=path.u8string();
        check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"fixture_open");}
    ~Database(){sqlite3_close(db);}
    void exec(const char* sql){check(sqlite3_exec(db,sql,nullptr,nullptr,nullptr)==SQLITE_OK,"fixture_sql");}
    int count(const char* sql){sqlite3_stmt* statement=nullptr;check(sqlite3_prepare_v2(db,sql,-1,&statement,nullptr)==SQLITE_OK,"fixture_prepare");
        check(sqlite3_step(statement)==SQLITE_ROW,"fixture_count");const auto value=sqlite3_column_int(statement,0);sqlite3_finalize(statement);return value;}
private:sqlite3* db{};
};
template<class F>void rejected(F fn,const char* expected){try{fn();}catch(const StorageError& error){check(std::string(error.what())==expected,"unexpected_rejection");return;}
    throw std::runtime_error("missing_rejection");}
GameSettlementRequest request(const std::string& match="match-1",GameOutcome outcome=GameOutcome::win) {
    std::array<std::uint32_t,21> thresholds{};
    for(std::size_t i=0;i<thresholds.size();++i)thresholds[i]=static_cast<std::uint32_t>(i)*50;
    return {match+":role-1",match,"fixture-stage",outcome,0,std::nullopt,
        {"isolated explicit test policy",{10,20,3},{5,8,1},{2,0,0},{3,4,0},thresholds,0}};
}
struct Fixture {
    std::filesystem::path path;Storage storage;std::int64_t actor;
    explicit Fixture(const std::filesystem::path& file):path(file),storage(file),
        actor(storage.dispatch("accounts.create",{{"username","settle-owner"},{"password","isolated"}}).at("account").at("role_id").get<std::int64_t>()) {
        Database(path).exec("UPDATE roles SET gold=100,coins=250,bank=300,level=0,experience=45,wins=0,losses=0,draws=0");
    }
    GameSettlementResult settle(const GameSettlementRequest& value){return storage.settle_game("settle-owner",actor,value);}
    void balance(double gold,int exp,int wins,int losses,int draws){const auto role=storage.roles_for_username("settle-owner").at(0);
        check(role.at("gold")==gold && role.at("experience")==exp && role.at("wins")==wins && role.at("losses")==losses && role.at("draws")==draws,
            "wrong_settlement_balance");check(role.at("coins")==250 && role.at("bank")==300,"unrelated_money_changed");}
};
void basic(const std::filesystem::path& path){
    Fixture f(path);const auto q=request();auto a=f.settle(q);
    check(!a.replayed && a.first_clear && a.reward.experience==10 && a.reward.gold_return==20 && a.reward.bonus_gold==3 &&
        a.level_before==0 && a.level_after==1,"first_result");f.balance(123,55,1,0,0);
    a=f.settle(q);check(a.replayed && a.first_clear && a.gold_after==123,"idempotent_result");f.balance(123,55,1,0,0);
    a=f.settle(request("match-2"));check(!a.first_clear && a.reward.experience==5,"repeat_reward");f.balance(132,60,2,0,0);
    (void)f.settle(request("match-3",GameOutcome::loss));f.balance(132,62,2,1,0);
    (void)f.settle(request("match-4",GameOutcome::draw));f.balance(136,65,2,1,1);
    a=f.settle(q);check(a.replayed && a.experience_after==55 && a.gold_after==123,"replay_historical_receipt");
    auto changed=q;changed.policy.first_win.gold_return=21;
    rejected([&]{f.settle(changed);},"game_settlement_operation_conflict");
    changed=q;changed.operation_id="another-id";
    rejected([&]{f.settle(changed);},"game_settlement_match_already_settled");
    rejected([&]{f.storage.settle_game("wrong-owner",f.actor,q);},"game_settlement_role_not_owned");
    Storage reopened(path);check(reopened.settle_game("settle-owner",f.actor,q).replayed,"reopen_replay");
    Database db(path);check(db.count("SELECT count(*) FROM game_settlements")==4,"settlement_count");
    check(db.count("SELECT wins FROM game_stage_progress")==2,"progress_count");
    check(db.count("SELECT count(*) FROM operations WHERE source='native-game-settlement'")==4,"operation_count");
}
void pledge(const std::filesystem::path& path){
    Fixture f(path);auto q=request();q.pawn_gold=10;
    rejected([&]{f.settle(q);},"game_settlement_pledge_binding_invalid");
    q.pledge_charge_operation="entry-1";
    rejected([&]{f.settle(q);},"game_settlement_pledge_not_debited");
    const auto charge=f.storage.reserve_game_pledge("settle-owner",f.actor,{"entry-1",q.match_id,q.stage_key,10});
    check(!charge.replayed && charge.gold_after==90,"entry_charge_failed");
    check(f.storage.reserve_game_pledge("settle-owner",f.actor,{"entry-1",q.match_id,q.stage_key,10}).replayed,"entry_replay_failed");
    q.policy.first_win.gold_return=30; // return actual stake plus20 reward
    (void)f.settle(q);f.balance(123,55,1,0,0);
    auto reused=request("other-match");reused.pawn_gold=10;reused.pledge_charge_operation="entry-1";
    rejected([&]{f.settle(reused);},"game_settlement_pledge_not_debited");
    rejected([&]{f.storage.refund_game_pledge("settle-owner",f.actor,{"refund-settled","entry-1","test"});},"game_pledge_not_held");
    (void)f.storage.consume_game_gold("settle-owner",f.actor,{10,"die-1","paid controlled die"});
    reused.pledge_charge_operation="die-1";
    rejected([&]{f.settle(reused);},"game_settlement_pledge_not_debited");
    reused.pawn_gold=0;
    rejected([&]{f.settle(reused);},"game_settlement_pledge_binding_invalid");
}
void pledge_refund(const std::filesystem::path& path) {
    Fixture f(path);const GameEntryPledgeRequest entry{"entry", "match-1", "fixture-stage",10};
    rejected([&]{f.storage.refund_game_pledge("settle-owner",f.actor,{"refund-none","entry","start failed"});},"game_pledge_not_reserved");
    auto bad=entry;bad.amount=101;
    rejected([&]{f.storage.reserve_game_pledge("settle-owner",f.actor,bad);},"game_pledge_insufficient_funds");
    (void)f.storage.reserve_game_pledge("settle-owner",f.actor,entry);f.balance(90,45,0,0,0);
    bad=entry;bad.operation_id="second-charge";
    rejected([&]{f.storage.reserve_game_pledge("settle-owner",f.actor,bad);},"game_pledge_match_already_reserved");
    auto q=request();
    rejected([&]{f.settle(q);},"game_settlement_pledge_binding_invalid");
    q.pawn_gold=10;q.pledge_charge_operation="entry";
    auto wrong=q;wrong.stage_key="another-stage";
    rejected([&]{f.settle(wrong);},"game_settlement_pledge_not_debited");
    const GameEntryPledgeRefund refund{"refund","entry","startup rejected after reservation"};
    const auto receipt=f.storage.refund_game_pledge("settle-owner",f.actor,refund);
    check(!receipt.replayed && receipt.gold_after==100,"refund_bad_balance");f.balance(100,45,0,0,0);
    check(f.storage.refund_game_pledge("settle-owner",f.actor,refund).replayed,"refund_replay");
    rejected([&]{f.storage.refund_game_pledge("settle-owner",f.actor,{"refund-again","entry","test"});},"game_pledge_not_held");
    rejected([&]{f.settle(q);},"game_settlement_pledge_not_held");
    rejected([&]{f.storage.reserve_game_pledge("settle-owner",f.actor,entry);},"game_pledge_not_held");
    f.balance(100,45,0,0,0);
}
void pledge_rollback(const std::filesystem::path& path) {
    Fixture f(path);Database db(path);
    const GameEntryPledgeRequest entry{"entry","match-1","fixture-stage",10};
    db.exec("CREATE TRIGGER fail_pledge BEFORE INSERT ON audit WHEN NEW.source='native-game-pledge' BEGIN SELECT RAISE(ABORT,'fixture'); END");
    bool failed=false;try{f.storage.reserve_game_pledge("settle-owner",f.actor,entry);}catch(const StorageError&){failed=true;}
    check(failed,"pledge_rollback_injection");f.balance(100,45,0,0,0);
    check(db.count("SELECT count(*) FROM operations WHERE operation_id='entry'")==0,"partial_pledge_receipt");
    db.exec("DROP TRIGGER fail_pledge");
    (void)f.storage.reserve_game_pledge("settle-owner",f.actor,entry);
    db.exec("CREATE TRIGGER fail_refund BEFORE INSERT ON operations WHEN NEW.source='native-game-pledge-refund' BEGIN SELECT RAISE(ABORT,'fixture'); END");
    failed=false;try{f.storage.refund_game_pledge("settle-owner",f.actor,{"refund","entry","start failed"});}catch(const StorageError&){failed=true;}
    check(failed,"refund_rollback_injection");f.balance(90,45,0,0,0);
    check(db.count("SELECT count(*) FROM game_entry_pledges WHERE state='held'")==1,"partial_refund_state");
    db.exec("DROP TRIGGER fail_refund");
    (void)f.storage.refund_game_pledge("settle-owner",f.actor,{"refund","entry","start failed"});
    f.balance(100,45,0,0,0);
}
void pledge_race(const std::filesystem::path& path) {
    Fixture f(path);Storage second(path);
    (void)f.storage.reserve_game_pledge("settle-owner",f.actor,{"entry","match-1","fixture-stage",10});
    auto q=request();q.pawn_gold=10;q.pledge_charge_operation="entry";q.policy.first_win.gold_return=30;
    std::promise<void> start;const auto ready=start.get_future().share();
    auto settle=std::async(std::launch::async,[&]{ready.wait();try{(void)f.settle(q);return true;}
        catch(const StorageError& e){check(std::string(e.what())=="game_settlement_pledge_not_held","race_settle_failure");return false;}});
    auto refund=std::async(std::launch::async,[&]{ready.wait();try{(void)second.refund_game_pledge("settle-owner",f.actor,{"refund","entry","start failed"});return true;}
        catch(const StorageError& e){check(std::string(e.what())=="game_pledge_not_held","race_refund_failure");return false;}});
    start.set_value();const auto won=settle.get();check(won!=refund.get(),"settlement_and_refund_both_committed");
    if(won)f.balance(123,55,1,0,0);else f.balance(100,45,0,0,0);
}
void rollback_and_bounds(const std::filesystem::path& path){
    Fixture f(path);Database db(path);
    for(const auto* table:{"audit","operations"}) {
        const auto sql=std::string("CREATE TRIGGER reject_settle BEFORE INSERT ON ")+table+
            " WHEN NEW.source='native-game-settlement' BEGIN SELECT RAISE(ABORT,'fixture'); END";
        db.exec(sql.c_str());bool failed=false;try{(void)f.settle(request());}catch(const StorageError&){failed=true;}
        check(failed,"injected_failure_missing");f.balance(100,45,0,0,0);
        check(db.count("SELECT count(*) FROM operations WHERE source='native-game-settlement'")==0,"partial_receipt_committed");
        db.exec("DROP TRIGGER reject_settle");
    }
    auto bad=request();bad.policy.first_win.experience=32768;
    rejected([&]{f.settle(bad);},"game_settlement_reward_out_of_range");
    bad=request();bad.policy.cumulative_level_experience[1]=0;
    rejected([&]{f.settle(bad);},"game_settlement_levels_invalid");
    bad=request();bad.policy.provenance.clear();
    rejected([&]{f.settle(bad);},"game_settlement_policy_missing");
    bad=request();bad.policy.winning_pledge_return=1;
    rejected([&]{f.settle(bad);},"game_settlement_pledge_return_invalid");
    db.exec("UPDATE roles SET experience=2147483647");
    rejected([&]{f.settle(request());},"game_settlement_experience_overflow");
    db.exec("UPDATE roles SET experience=45,gold=9007199254740992");
    rejected([&]{f.settle(request());},"game_settlement_gold_precision_invalid");
    db.exec("UPDATE roles SET gold=100,wins=2147483647");
    rejected([&]{f.settle(request());},"game_settlement_counter_overflow");
    db.exec("UPDATE roles SET wins=0,level=20");
    check(f.settle(request()).level_after==20,"admin_test_level_downgraded");
}
void concurrent_first_clear(const std::filesystem::path& path,bool same_match){
    Fixture f(path);std::vector<std::unique_ptr<Storage>> writers;
    for(int i=0;i<4;++i)writers.push_back(std::make_unique<Storage>(path));
    std::promise<void> start;const auto ready=start.get_future().share();std::vector<std::future<GameSettlementResult>> results;
    for(std::size_t i=0;i<writers.size();++i)results.push_back(std::async(std::launch::async,[&,i]{ready.wait();
        return writers[i]->settle_game("settle-owner",f.actor,request(same_match?"same":"match-"+std::to_string(i)));}));
    start.set_value();int committed=0,first=0;
    for(auto& pending:results){check(pending.wait_for(std::chrono::seconds(10))==std::future_status::ready,"settlement_timeout");
        const auto result=pending.get();committed+=!result.replayed;first+=!result.replayed && result.first_clear;}
    check(committed==(same_match?1:4) && first==1,"first_clear_or_idempotency_race");
    f.balance(same_match?123:150,same_match?55:70,same_match?1:4,0,0);
}
}
int main(){try{
    const auto root=std::filesystem::temp_directory_path()/("game-settlement-tests-"+std::to_string(GetCurrentProcessId())+"-"+
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));std::filesystem::create_directories(root);
    basic(root/"basic.sqlite3");pledge(root/"pledge.sqlite3");pledge_refund(root/"refund.sqlite3");rollback_and_bounds(root/"rollback.sqlite3");
    pledge_rollback(root/"pledge-rollback.sqlite3");pledge_race(root/"pledge-race.sqlite3");
    concurrent_first_clear(root/"same.sqlite3",true);concurrent_first_clear(root/"different.sqlite3",false);
    std::cout<<"PASS settlement persistence, pledges, first clear, rollback, replay, concurrent transactions\n";
}catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}}
