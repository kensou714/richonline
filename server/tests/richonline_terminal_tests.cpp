#include "richonline_terminal.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <chrono>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
template<class F>void rejected(F fn){try{fn();}catch(const std::exception&){return;}throw std::runtime_error("missing_rejection");}
}
int main(){try{
    using namespace richnet;
    const auto compatibility=richonline_boss_result_byte18_compatibility(
        "cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77",3);
    check(compatibility.value==0 && !compatibility.evidence.empty(),"audited_constructor_value");
    const auto graphics=richonline_boss_result_byte18_compatibility(
        "a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2",3);
    check(graphics.value==compatibility.value && graphics.evidence.find(compatibility.evidence)==0 &&
        graphics.evidence.find("graphics-byte18-chain.json")!=std::string::npos,"graphics_audit_chain_missing");
    rejected([&]{(void)richonline_boss_result_byte18_compatibility(
        "a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2",4);});
    rejected([&]{(void)richonline_boss_result_byte18_compatibility(
        "a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c3",3);});
    rejected([&]{(void)richonline_boss_result_byte18_compatibility("unreviewed-client",3);});
    rejected([&]{(void)richonline_boss_result_byte18_compatibility(
        "cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77",4);});
    const RichonlineTerminalRules rules{"explicit fixture elimination rule",RichonlineSimultaneousDefeat::human_loss,0,1,1,0x63,false};
    const RichonlineTerminalSnapshot initial{3,0,{1,2},{}};
    auto plan=plan_richonline_terminal(initial,std::array<std::int8_t,1>{1},rules);
    check(!plan.outcome && plan.newly_eliminated==std::vector<std::int8_t>{1},"early_terminal");
    auto repeated=plan_richonline_terminal(plan.after,std::array<std::int8_t,1>{1},rules);
    check(!repeated.outcome && repeated.newly_eliminated.empty(),"repeat_bankruptcy");
    plan=plan_richonline_terminal(plan.after,std::array<std::int8_t,1>{2},rules);
    check(plan.outcome==GameOutcome::win,"last_boss_win");
    auto simultaneous=plan_richonline_terminal(initial,std::array<std::int8_t,3>{0,1,2},rules);
    check(simultaneous.outcome==GameOutcome::loss,"simultaneous_loss_rule");
    auto draw=rules;draw.simultaneous_defeat=RichonlineSimultaneousDefeat::draw;
    check(plan_richonline_terminal(initial,std::array<std::int8_t,3>{0,1,2},draw).outcome==GameOutcome::draw,"simultaneous_draw_rule");
    rejected([&]{(void)plan_richonline_terminal(initial,std::array<std::int8_t,1>{7},rules);});
    const auto path=std::filesystem::temp_directory_path()/("terminal-test-"+std::to_string(GetCurrentProcessId())+"-"+
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())+".sqlite3");
    Storage storage(path);const auto role=storage.dispatch("accounts.create",{{"username","terminal"},{"password","fixture"}}).at("account").at("role_id").get<std::int64_t>();
    std::array<std::uint32_t,21> levels{};for(std::size_t i=0;i<levels.size();++i)levels[i]=static_cast<std::uint32_t>(i)*50;
    const GameSettlementRequest request{"terminal-op","match-fixture","fixture-stage",GameOutcome::loss,0,{},
        {"fixture reward",{10,20,0},{5,8,0},{0,0,0},{0,0,0},levels,0}};
    const auto receipt=commit_richonline_terminal(storage,"terminal",role,request,5,2,plan,rules);
    check(!receipt.replayed && receipt.first_clear,"settlement_receipt");
    auto pending=storage.pending_game_settlements("terminal",role);check(pending.size()==1,"outbox_missing");
    auto messages=recover_richonline_terminal_messages(pending[0],"match-fixture",5);
    check(messages.size()==5 && read_le(View(messages[0].game_plain).first(2))==0x400d &&
        messages.back().lobby->wire_type==58,"terminal_sequence");
    rejected([&]{(void)recover_richonline_terminal_messages(pending[0],"other-match",5);});
    rejected([&]{storage.advance_game_settlement_outbox("terminal",role,"terminal-op",2);});
    // Failed send does not checkpoint. Reopening yields the same pending intent.
    Storage reopened(path);check(reopened.pending_game_settlements("terminal",role)[0].next_message==0,"outbox_not_durable");
    storage.advance_game_settlement_outbox("terminal",role,"terminal-op",0);
    storage.advance_game_settlement_outbox("terminal",role,"terminal-op",0);
    pending=reopened.pending_game_settlements("terminal",role);check(pending[0].next_message==1,"outbox_checkpoint_replay");
    check(commit_richonline_terminal(storage,"terminal",role,request,5,2,plan,rules).replayed,"terminal_replay");
    for(std::uint32_t i=1;i<5;++i)storage.advance_game_settlement_outbox("terminal",role,"terminal-op",i);
    check(storage.pending_game_settlements("terminal",role).empty(),"outbox_not_finished");
    // Outbox insertion failure must roll back reward and operation together.
    sqlite3* raw=nullptr;const auto utf8=path.u8string();check(sqlite3_open(reinterpret_cast<const char*>(utf8.c_str()),&raw)==SQLITE_OK,"fixture_open");
    check(sqlite3_exec(raw,"CREATE TRIGGER fail_outbox BEFORE INSERT ON game_settlement_outbox BEGIN SELECT RAISE(ABORT,'fixture'); END",nullptr,nullptr,nullptr)==SQLITE_OK,"fixture_trigger");
    const auto before=storage.roles_for_username("terminal");auto retry=request;retry.operation_id="failure-op";retry.match_id="failure-match";
    rejected([&]{(void)commit_richonline_terminal(storage,"terminal",role,retry,6,2,plan,rules);});
    check(storage.roles_for_username("terminal")==before,"outbox_failure_partial_reward");
    check(sqlite3_exec(raw,"DROP TRIGGER fail_outbox",nullptr,nullptr,nullptr)==SQLITE_OK,"fixture_drop");sqlite3_close(raw);
    check(!commit_richonline_terminal(storage,"terminal",role,retry,6,2,plan,rules).replayed,"rolledback_operation_retained");
    std::cout<<"PASS terminal elimination, explicit simultaneous rule, atomic durable outbox and delivery checkpoints\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
