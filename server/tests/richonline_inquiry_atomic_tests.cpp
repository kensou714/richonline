#include "richonline_ranking.hpp"
#include "richonline_terminal_coordinator.hpp"
#include "storage.hpp"
#include <windows.h>
#include <sqlite3.h>
#include <bit>
#include <chrono>
#include <iostream>
#include <memory>

namespace {
using namespace richnet;
void check(bool condition,const char* message){if(!condition)throw std::runtime_error(message);}
template<class F>void rejects(F action,const char* message) {
    try{action();}catch(const std::exception& error){check(std::string(error.what())==message,error.what());return;}
    throw std::runtime_error("expected rejection absent");
}
struct Database {
    sqlite3* db{};
    explicit Database(const std::filesystem::path& path) {
        const auto name=path.u8string();
        check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"fixture database open");
    }
    ~Database(){sqlite3_close(db);}
    void exec(const char* sql){check(sqlite3_exec(db,sql,nullptr,nullptr,nullptr)==SQLITE_OK,"fixture SQL");}
    std::int64_t scalar(const char* sql) {
        sqlite3_stmt* value{};check(sqlite3_prepare_v2(db,sql,-1,&value,nullptr)==SQLITE_OK,"fixture scalar prepare");
        const auto result=sqlite3_step(value);const auto count=sqlite3_column_int64(value,0);sqlite3_finalize(value);
        check(result==SQLITE_ROW,"fixture scalar step");return count;
    }
};
GameSettlementRequest request(const std::string& match,std::uint64_t score,bool with_delivery=true) {
    std::array<std::uint32_t,21> levels{};
    for(std::size_t index=0;index<levels.size();++index)levels[index]=static_cast<std::uint32_t>(index)*100;
    const GameSettlementReward reward{1,2,3,{}};
    GameSettlementRequest value{match+":settlement",match,"atomic-stage",GameOutcome::win,0,{},
        {"atomic test policy",reward,reward,reward,reward,levels,0},{},
        GameSettlementAchievement{RichonlineAchievement::cash_earned,score,richonline_cash_earned_policy,2}};
    if(with_delivery)value.delivery=GameSettlementDelivery{5,2,0,0,0x63,false,{1}};
    return value;
}
Bytes query(std::uint32_t type) {
    Bytes value{13,10};append_le(value,type,4);append_le(value,3,4);
    const auto name=richonline_auxiliary_name("atomicuser");value.insert(value.end(),name.begin(),name.end());return value;
}
std::int32_t i32(const Bytes& bytes,std::size_t offset){return std::bit_cast<std::int32_t>(read_le(View(bytes).subspan(offset,4)));}
std::uint32_t wins(Storage& storage){return storage.roles_for_username("atomicuser").at(0).at("wins").get<std::uint32_t>();}
void process_commit_then_crash(const std::filesystem::path& path) {
    Storage storage(path);const auto role=storage.roles_for_username("atomicuser").at(0).at("role_id").get<std::int64_t>();
    (void)storage.settle_game("atomicuser",role,request("crash-after-commit",80));
    // Deliberately skip every C++ destructor and all result network delivery.
    ExitProcess(73);
}
void crash_child(const std::filesystem::path& path) {
    std::wstring executable(32768,L'\0');
    const auto count=GetModuleFileNameW(nullptr,executable.data(),static_cast<DWORD>(executable.size()));
    check(count!=0&&count<executable.size(),"child executable path");executable.resize(count);
    auto command=L"\""+executable+L"\" --commit-and-crash \""+path.wstring()+L"\"";
    STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION process{};
    check(CreateProcessW(executable.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process)!=0,"child create");
    const auto wait=WaitForSingleObject(process.hProcess,10000);
    DWORD code{};const auto read=GetExitCodeProcess(process.hProcess,&code);
    CloseHandle(process.hThread);CloseHandle(process.hProcess);
    check(wait==WAIT_OBJECT_0&&read&&code==73,"child did not crash after commit");
}
void atomics(const std::filesystem::path& path) {
    std::int64_t role{};
    {
        Storage storage(path);role=storage.dispatch("accounts.create",{{"username","atomicuser"},{"password","test"}})
            .at("account").at("role_id").get<std::int64_t>();
        auto legacy=request("legacy",0);legacy.achievement.reset();
        check(!storage.settle_game("atomicuser",role,legacy).replayed,"legacy first commit");
        check(storage.settle_game("atomicuser",role,legacy).replayed,"legacy canonical changed");
        Database db(path);
        check(db.scalar("SELECT json_type(request,'$.achievement') IS NULL FROM operations WHERE operation_id='legacy:settlement'")==1,"legacy received new null key");
        check(db.scalar("SELECT count(*) FROM sqlite_master WHERE name='richonline_achievement_matches'")==0,"legacy fabricated metrics schema");
    }
    crash_child(path);
    Storage storage(path);Database db(path);RichonlineRankingStore ranks(path);
    check(i32(*ranks.response(query(0)),44)==80&&i32(*ranks.response(query(2)),8)==1,"committed metric lost on process exit");
    check(db.scalar("SELECT count(*) FROM game_settlement_outbox WHERE match_id='crash-after-commit' AND next_message=0")==1,"crash lost result outbox");
    check(db.scalar("SELECT json_extract(request,'$.achievement.ledger_revision') FROM operations WHERE operation_id='crash-after-commit:settlement'")==2,"missing ledger revision provenance");
    check(db.scalar("SELECT COUNT(*) FROM richonline_achievement_policies")==1,"unobserved categories were registered");
    const auto before=wins(storage);
    check(storage.settle_game("atomicuser",role,request("crash-after-commit",80)).replayed&&wins(storage)==before,"crash retry double win");
    check(db.scalar("SELECT COUNT(*) FROM richonline_achievement_matches WHERE match_id='crash-after-commit'")==1,"crash retry double metric");
    auto altered=request("crash-after-commit",81);
    rejects([&]{storage.settle_game("atomicuser",role,altered);},"game_settlement_operation_conflict");
    altered=request("crash-after-commit",80);altered.achievement->ledger_revision=3;
    rejects([&]{storage.settle_game("atomicuser",role,altered);},"game_settlement_operation_conflict");
    const auto fail=[&](const char* trigger,const char* match) {
        db.exec(trigger);const auto old=wins(storage);bool failed=false;
        try{storage.settle_game("atomicuser",role,request(match,11));}catch(const StorageError&){failed=true;}
        check(failed&&wins(storage)==old,"fault did not rollback role settlement");
        check(db.scalar("SELECT COUNT(*) FROM richonline_achievement_matches")==1,"failed transaction left metric");
        check(db.scalar("SELECT COUNT(*) FROM game_settlements")==2,"failed transaction left settlement");
        check(db.scalar("SELECT COUNT(*) FROM operations WHERE source='native-game-settlement'")==2,"failed transaction left operation");
        db.exec("DROP TRIGGER achievement_fault");
    };
    fail("CREATE TRIGGER achievement_fault BEFORE INSERT ON richonline_achievement_matches BEGIN SELECT RAISE(ABORT,'metric fault'); END","metric-fault");
    fail("CREATE TRIGGER achievement_fault BEFORE INSERT ON game_settlement_outbox BEGIN SELECT RAISE(ABORT,'after metric fault'); END","outbox-fault");
    check(!storage.settle_game("atomicuser",role,request("outbox-fault",11)).replayed,"retry did not commit");
    check(i32(*ranks.response(query(0)),44)==91,"retry metric incorrect");
    auto overflow=request("overflow",2147483647);
    const auto old=wins(storage);
    rejects([&]{storage.settle_game("atomicuser",role,overflow);},"ranking_achievement_score_out_of_wire_range");
    check(wins(storage)==old&&i32(*ranks.response(query(0)),44)==91,"sum overflow partially settled");
    auto policy=request("policy-conflict",12);policy.achievement->policy="different local rule";
    rejects([&]{storage.settle_game("atomicuser",role,policy);},"ranking_achievement_policy_conflict");
    check(wins(storage)==old,"policy conflict partially settled");
    // A committed operation is never silently repaired from missing evidence.
    db.exec("DELETE FROM richonline_achievement_matches WHERE match_id='outbox-fault'");
    rejects([&]{storage.settle_game("atomicuser",role,request("outbox-fault",11));},"ranking_achievement_committed_record_invalid");
    RichonlineAchievementStore writer(path);
    rejects([&]{writer.record_match("atomicuser",role,"outbox-fault",RichonlineAchievement::cash_earned,11,richonline_cash_earned_policy);},"ranking_achievement_committed_record_invalid");
}
RichonlineTerminalContext terminal_context(std::int64_t role,const std::string& match) {
    auto value=request(match,0,false);value.achievement.reset();
    return {"atomicuser",role,5,2,value,{3,0,{1},{}},
        {"explicit test rule",RichonlineSimultaneousDefeat::human_loss,0,1,1,0x63,false},"test byte18"};
}
void coordinator(const std::filesystem::path& path) {
    Storage storage(path);const auto role=storage.dispatch("accounts.create",{{"username","atomicuser"},{"password","test"}})
        .at("account").at("role_id").get<std::int64_t>();
    Database db(path);
    auto ledger=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{1000,500,0,0},{1000,500,0,0}});
    RichonlineTerminalCoordinator flow(storage,terminal_context(role,"observed"));
    rejects([&]{flow.bind_earned_cash(ledger,1);},"richonline_terminal_income_binding_invalid");
    flow.bind_earned_cash(ledger,0);
    rejects([&]{flow.bind_earned_cash(ledger,0);},"richonline_terminal_income_binding_invalid");
    flow.prepare_start();flow.activate();
    ledger->adjust(0,ledger->snapshot(0),{-100,100,0,0});
    ledger->adjust(0,ledger->snapshot(0),{70,0,0,0});
    ledger->adjust(1,ledger->snapshot(1),{900,0,0,0});
    check(flow.bankrupt(std::array<std::int8_t,1>{1}).action==RichonlineTerminalAction::deliver,"terminal income commit");
    RichonlineRankingStore ranks(path);
    check(i32(*ranks.response(query(0)),44)==70,"terminal captured wrong actor income");
    check(db.scalar("SELECT json_extract(request,'$.achievement.ledger_revision') FROM operations WHERE operation_id='observed:settlement'")==2,"terminal capture revision mismatch");
    check(flow.bankrupt(std::array<std::int8_t,1>{1}).action==RichonlineTerminalAction::deliver,"duplicate terminal changed state");
    check(flow.abandon("after commit").action==RichonlineTerminalAbandonAction::already_terminal,"disconnect resettled win");
    auto next=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{1000,500,0,0},{1000,500,0,0}});
    RichonlineTerminalCoordinator retry(storage,terminal_context(role,"freeze-retry"));
    retry.bind_earned_cash(next,0);retry.prepare_start();retry.activate();
    next->adjust(0,next->snapshot(0),{30,0,0,0});
    db.exec("CREATE TRIGGER achievement_fault BEFORE INSERT ON game_settlement_outbox BEGIN SELECT RAISE(ABORT,'freeze fault'); END");
    check(retry.bankrupt(std::array<std::int8_t,1>{1}).action==RichonlineTerminalAction::abort_live_game,"fault did not stop result");
    check(i32(*ranks.response(query(0)),44)==70,"failed result leaked metric");
    db.exec("DROP TRIGGER achievement_fault");
    // Deliberately mutate the test ledger after the failed terminal attempt.
    // Retry must keep the already captured terminal score and revision.
    next->adjust(0,next->snapshot(0),{300,0,0,0});
    check(retry.abandon("retry cleanup").action==RichonlineTerminalAbandonAction::loss_persisted,"failed result cleanup");
    check(i32(*ranks.response(query(0)),44)==100,"retry recaptured later funds");
    check(db.scalar("SELECT json_extract(request,'$.achievement.ledger_revision') FROM operations WHERE operation_id='freeze-retry:settlement'")==1,"retry changed frozen revision");
    check(retry.abandon("duplicate cleanup").action==RichonlineTerminalAbandonAction::already_terminal,"cleanup double metric");
    auto aborted_ledger=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{1000,500,0,0},{1000,500,0,0}});
    RichonlineTerminalCoordinator aborted(storage,terminal_context(role,"never-started"));
    aborted.bind_earned_cash(aborted_ledger,0);aborted.prepare_start();aborted.abort_start("startup aborted");
    check(db.scalar("SELECT COUNT(*) FROM richonline_achievement_matches WHERE match_id='never-started'")==0,"aborted match registered zero");
    auto fresh=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{1000,500,0,0},{1000,500,0,0}});
    RichonlineTerminalCoordinator leave(storage,terminal_context(role,"observed-leave"));
    leave.bind_earned_cash(fresh,0);leave.prepare_start();leave.activate();
    fresh->adjust(0,fresh->snapshot(0),{0,17,0,0});
    check(leave.abandon("normal active disconnect").action==RichonlineTerminalAbandonAction::loss_persisted,"active disconnect did not settle");
    check(i32(*ranks.response(query(0)),44)==117,"active disconnect omitted actual income");
    check(db.scalar("SELECT COUNT(*) FROM game_settlement_outbox WHERE match_id='observed-leave'")==0,"disconnect emitted result outbox");
}
}
int main(int argc,char** argv){try{
    if(argc==3&&std::string(argv[1])=="--commit-and-crash"){process_commit_then_crash(std::filesystem::path(argv[2]));return 2;}
    const auto root=std::filesystem::temp_directory_path()/("inquiry-atomic-"+std::to_string(GetCurrentProcessId())+"-"+
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    atomics(root/"atomic.sqlite3");coordinator(root/"coordinator.sqlite3");
    std::cout<<"PASS achievement atomic settlement, crash-before-delivery durability, replay, rollback, ledger binding and frozen retry\n";
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
