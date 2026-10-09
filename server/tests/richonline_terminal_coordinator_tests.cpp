#include "richonline_terminal_coordinator.hpp"
#include <windows.h>
#include <sqlite3.h>
#include <chrono>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
template<class F>void rejected(F fn){try{fn();}catch(const std::exception&){return;}throw std::runtime_error("missing_rejection");}
void sql(const std::filesystem::path& path,const char* command) {
    sqlite3* db=nullptr;const auto name=path.u8string();
    check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"fixture_open");
    const auto result=sqlite3_exec(db,command,nullptr,nullptr,nullptr);sqlite3_close(db);check(result==SQLITE_OK,"fixture_sql");
}
std::int64_t scalar(const std::filesystem::path& path,const char* command) {
    sqlite3* db=nullptr;const auto name=path.u8string();
    check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"fixture_open");
    sqlite3_stmt* statement=nullptr;
    check(sqlite3_prepare_v2(db,command,-1,&statement,nullptr)==SQLITE_OK,"fixture_prepare");
    check(sqlite3_step(statement)==SQLITE_ROW,"fixture_scalar");
    const auto value=sqlite3_column_int64(statement,0);sqlite3_finalize(statement);sqlite3_close(db);return value;
}
RichonlineTerminalContext context(std::int64_t role,const std::string& match) {
    std::array<std::uint32_t,21> levels{};for(std::size_t i=0;i<levels.size();++i)levels[i]=static_cast<std::uint32_t>(i)*50;
    return {"coordinator",role,5,2,{match+":settlement",match,"fixture-stage",GameOutcome::loss,10,{},
        {"fixture resource reward",{10,30,0},{5,18,0},{0,0,0},{0,0,0},levels,10}},
        {3,0,{1,2},{}},{"explicit fixture elimination rule",RichonlineSimultaneousDefeat::human_loss,0,1,1,0x63,false},
        "fixture supplied byte; not production evidence"};
}
}
int main(){try {
    using namespace richnet;
    const auto path=std::filesystem::temp_directory_path()/("terminal-coordinator-test-"+std::to_string(GetCurrentProcessId())+"-"+
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())+".sqlite3");
    Storage storage(path);const auto role=storage.dispatch("accounts.create",{{"username","coordinator"},{"password","fixture"}}).at("account").at("role_id").get<std::int64_t>();
    sql(path,"UPDATE roles SET gold=100,level=0,experience=0,wins=0,losses=0,draws=0");
    const auto gold=[&]{return storage.roles_for_username("coordinator").at(0).at("gold").get<double>();};
    const auto losses=[&]{return storage.roles_for_username("coordinator").at(0).at("losses").get<std::uint32_t>();};
    {
        RichonlineTerminalCoordinator flow(storage,context(role,"startup-abort"));
        rejected([&]{flow.activate();});
        check(!flow.prepare_start()->replayed && gold()==90,"startup_actual_debit");
        check(flow.prepare_start()->replayed && gold()==90,"startup_no_duplicate_debit");
        check(flow.abort_start("fixture startup failed")->gold_after==100 && gold()==100,"startup_refund_actual_hold");
        rejected([&]{flow.activate();});
    }
    {
        RichonlineTerminalCoordinator flow(storage,context(role,"prepared-release"));
        (void)flow.prepare_start();const auto before=losses();
        const auto result=flow.abandon("game disconnected before activation");
        check(result.action==RichonlineTerminalAbandonAction::startup_refunded && result.startup_refund->gold_after==100,
            "prepared_release_returns_real_hold");
        check(losses()==before && flow.abandon("duplicate cleanup").action==RichonlineTerminalAbandonAction::already_terminal,
            "prepared_release_no_loss_or_duplicate_credit");
        check(scalar(path,"SELECT count(*) FROM game_entry_pledges WHERE match_id='prepared-release' AND state='held'")==0,
            "prepared_release_no_orphan_pledge");
    }
    {
        auto config=context(role,"playing-release");config.settlement.policy.loss={2,3,0};
        RichonlineTerminalCoordinator flow(storage,config);(void)flow.prepare_start();flow.activate();
        const auto before=gold();const auto before_losses=losses();const auto result=flow.abandon("C2S0A2B graceful leave");
        check(result.action==RichonlineTerminalAbandonAction::loss_persisted && result.settlement->reward.experience==2 &&
            gold()==before+3 && losses()==before_losses+1,"playing_release_uses_explicit_loss_policy");
        check(!flow.next_transmission() && storage.pending_game_settlements("coordinator",role).empty(),
            "leave_after_ack_no_game_result_outbox");
        check(flow.abandon("duplicate EOF cleanup").action==RichonlineTerminalAbandonAction::already_terminal &&
            losses()==before_losses+1,"playing_release_is_idempotent");
        check(scalar(path,"SELECT count(*) FROM game_entry_pledges WHERE match_id='playing-release' AND state='settled'")==1,
            "playing_release_closes_real_hold");
    }
    {
        RichonlineTerminalCoordinator flow(storage,context(role,"complete"));
        const auto before_start=gold();
        (void)flow.prepare_start();flow.activate();rejected([&]{(void)flow.abort_start("cannot refund live game");});
        auto step=flow.bankrupt(std::array<std::int8_t,1>{1});
        check(step.action==RichonlineTerminalAction::continue_play && step.game_messages.size()==2,"partial_boss_elimination");
        check(flow.bankrupt(std::array<std::int8_t,1>{1}).game_messages.empty(),"duplicate_elimination");
        step=flow.bankrupt(std::array<std::int8_t,1>{2});
        check(step.action==RichonlineTerminalAction::deliver && gold()==before_start+20,"terminal_reward_once");
        check(flow.bankrupt(std::array<std::int8_t,1>{2}).action==RichonlineTerminalAction::deliver && gold()==before_start+20,"terminal_repeated_no_reward");
        const auto planned=flow.pending_game_messages();
        check(planned.size()==4 && planned.front()==flow.next_transmission()->game_plain,
            "remaining_game_snapshot_keeps_order_and_excludes_lobby");
        check(flow.pending_game_messages()==planned && scalar(path,"SELECT next_message FROM game_settlement_outbox WHERE match_id='complete'")==0,
            "planning_never_checkpoints_outbox");
        const auto sequence=flow.next_transmission()->sequence;
        rejected([&]{flow.confirm_sent(sequence+1);});
        check(flow.next_transmission()->sequence==sequence,"failed_send_does_not_checkpoint");
        while(const auto* message=flow.next_transmission()) {
            if(message->transport==RichonlineSettlementTransport::lobby)check(message->lobby->wire_type==58,"finished_must_keep_room");
            flow.confirm_sent(message->sequence);
        }
        check(flow.phase()==RichonlineTerminalPhase::finished && storage.pending_game_settlements("coordinator",role).empty(),"finish_cursor");
        check(flow.pending_game_messages().empty(),"finished_game_snapshot_empty");
        const auto before=losses();
        check(flow.abandon("normal finished session released").action==RichonlineTerminalAbandonAction::already_terminal &&
            losses()==before,"normal_finish_never_becomes_loss");
    }
    {
        auto unknown=context(role,"unverified");unknown.result_byte18_evidence.clear();
        RichonlineTerminalCoordinator flow(storage,unknown);(void)flow.prepare_start();flow.activate();
        const auto before=gold();const auto step=flow.bankrupt(std::array<std::int8_t,1>{0});
        check(step.action==RichonlineTerminalAction::abort_live_game && !step.diagnostic.empty() && !flow.next_transmission(),"unknown_field_no_fake_settlement_or_wait");
        check(gold()==before && storage.pending_game_settlements("coordinator",role).empty(),"unknown_field_no_award");
        check(flow.abandon("unverified result teardown").action==RichonlineTerminalAbandonAction::loss_persisted &&
            !flow.next_transmission(),"unverified_path_can_close_held_pledge_without_fabricated_packet");
    }
    {
        RichonlineTerminalCoordinator flow(storage,context(role,"database-failure"));(void)flow.prepare_start();flow.activate();
        sql(path,"CREATE TRIGGER coordinator_fail BEFORE INSERT ON game_settlement_outbox BEGIN SELECT RAISE(ABORT,'fixture'); END");
        const auto before=gold();const auto step=flow.bankrupt(std::array<std::int8_t,2>{1,2});
        check(step.action==RichonlineTerminalAction::abort_live_game && flow.phase()==RichonlineTerminalPhase::recovery_required && gold()==before,"persistence_failure_bounded_and_atomic");
        sql(path,"DROP TRIGGER coordinator_fail");
        check(flow.abandon("failed result teardown").action==RichonlineTerminalAbandonAction::loss_persisted,
            "failed_uncommitted_result_can_close_as_loss");
    }
    {
        RichonlineTerminalCoordinator flow(storage,context(role,"checkpoint-failure"));(void)flow.prepare_start();flow.activate();
        check(flow.bankrupt(std::array<std::int8_t,2>{1,2}).action==RichonlineTerminalAction::deliver,"checkpoint_fixture_commit");
        sql(path,"CREATE TRIGGER coordinator_fail BEFORE UPDATE ON game_settlement_outbox BEGIN SELECT RAISE(ABORT,'fixture'); END");
        rejected([&]{flow.confirm_sent(flow.next_transmission()->sequence);});
        check(flow.phase()==RichonlineTerminalPhase::recovery_required && !flow.next_transmission(),"sent_packet_must_not_blind_replay");
        sql(path,"DROP TRIGGER coordinator_fail");
        const auto before=losses();
        check(flow.abandon("checkpoint failed; preserve committed victory").action==RichonlineTerminalAbandonAction::already_terminal &&
            losses()==before,"committed_result_preserved_during_recovery");
    }
    {
        RichonlineTerminalCoordinator flow(storage,context(role,"abandon-retry"));(void)flow.prepare_start();flow.activate();
        sql(path,"CREATE TRIGGER coordinator_fail BEFORE INSERT ON game_settlements BEGIN SELECT RAISE(ABORT,'fixture'); END");
        const auto before=losses();
        check(flow.abandon("socket EOF").action==RichonlineTerminalAbandonAction::recovery_required && losses()==before,
            "abandon_failure_is_bounded_and_atomic");
        sql(path,"DROP TRIGGER coordinator_fail");
        check(flow.abandon("retry EOF cleanup").action==RichonlineTerminalAbandonAction::loss_persisted && losses()==before+1,
            "abandon_retry_closes_match_once");
    }
    std::cout<<"PASS terminal coordinator: escrow, partial elimination, durable result, leave/disconnect loss, bounded recovery\n";
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
