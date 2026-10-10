#include "richonline_terminal_coordinator.hpp"
#include <algorithm>

namespace richnet {
RichonlineTerminalCoordinator::RichonlineTerminalCoordinator(Storage& storage,RichonlineTerminalContext context)
    : storage_(storage),context_(std::move(context)) {
    if(context_.settlement.delivery || context_.settlement.pledge_charge_operation || context_.settlement.achievement)
        throw CodecError("richonline_terminal_coordinator_requires_unreserved_request");
    if(context_.settlement.operation_id.empty() || context_.settlement.match_id.empty() ||
        context_.settlement.stage_key.empty())throw CodecError("richonline_terminal_coordinator_identity_missing");
    const auto initial=plan_richonline_terminal(context_.roster,{},context_.rules);
    if(initial.outcome || !context_.roster.eliminated_slots.empty())
        throw CodecError("richonline_terminal_coordinator_requires_fresh_roster");
    (void)richonline_lobby_game_finished(context_.room_id);
}
void RichonlineTerminalCoordinator::bind_earned_cash(std::shared_ptr<const RichonlineGameLedger> ledger,std::uint8_t actor) {
    if(phase_!=RichonlineTerminalPhase::prepared || income_ledger_ || !ledger ||
        actor!=static_cast<std::uint8_t>(context_.roster.human_slot))
        throw CodecError("richonline_terminal_income_binding_invalid");
    (void)ledger->income_snapshot(actor);
    income_ledger_=std::move(ledger);income_actor_=actor;
}
void RichonlineTerminalCoordinator::freeze_achievement() {
    if(!income_ledger_ || context_.settlement.achievement)return;
    const auto snapshot=income_ledger_->income_snapshot(income_actor_);
    context_.settlement.achievement=GameSettlementAchievement{RichonlineAchievement::cash_earned,
        snapshot.earned_cash,richonline_cash_earned_policy,snapshot.ledger_revision};
}
std::optional<GameEntryPledgeResult> RichonlineTerminalCoordinator::prepare_start() {
    if(phase_!=RichonlineTerminalPhase::prepared)throw CodecError("richonline_terminal_start_phase");
    const auto& request=context_.settlement;
    if(request.pawn_gold==0){reserved_=true;return {};}
    const auto operation=request.operation_id+":entry";
    auto receipt=storage_.reserve_game_pledge(context_.username,context_.role_id,
        {operation,request.match_id,request.stage_key,request.pawn_gold});
    context_.settlement.pledge_charge_operation=operation;reserved_=true;return receipt;
}
void RichonlineTerminalCoordinator::activate() {
    if(phase_!=RichonlineTerminalPhase::prepared || !reserved_)
        throw CodecError("richonline_terminal_start_not_reserved");
    activated_=true;phase_=RichonlineTerminalPhase::playing;
}
std::optional<GameEntryPledgeResult> RichonlineTerminalCoordinator::abort_start(const std::string& reason) {
    if(phase_!=RichonlineTerminalPhase::prepared)throw CodecError("richonline_terminal_abort_started_match");
    std::optional<GameEntryPledgeResult> result;
    if(context_.settlement.pledge_charge_operation)
        result=storage_.refund_game_pledge(context_.username,context_.role_id,
            {context_.settlement.operation_id+":startup-refund",*context_.settlement.pledge_charge_operation,reason});
    phase_=RichonlineTerminalPhase::aborted;return result;
}
RichonlineTerminalAbandonResult RichonlineTerminalCoordinator::abandon(const std::string& reason) {
    if(reason.empty() || reason.size()>1024 || reason.find('\0')!=std::string::npos)
        throw CodecError("richonline_terminal_abandon_reason_invalid");
    if(settled_ || phase_==RichonlineTerminalPhase::finished || phase_==RichonlineTerminalPhase::aborted) {
        // A socket can disappear during result delivery. Keep the real committed
        // result/outbox for explicit recovery and stop writing this dead game.
        if(phase_==RichonlineTerminalPhase::delivering)phase_=RichonlineTerminalPhase::recovery_required;
        return {RichonlineTerminalAbandonAction::already_terminal,{},{},reason};
    }
    try {
        if(!activated_) {
            std::optional<GameEntryPledgeResult> receipt;
            if(context_.settlement.pledge_charge_operation)
                receipt=storage_.refund_game_pledge(context_.username,context_.role_id,
                    {context_.settlement.operation_id+":startup-refund",*context_.settlement.pledge_charge_operation,reason});
            phase_=RichonlineTerminalPhase::aborted;
            return {RichonlineTerminalAbandonAction::startup_refunded,std::move(receipt),{},reason};
        }
        freeze_achievement();
        auto request=context_.settlement;
        request.outcome=GameOutcome::loss;
        request.delivery.reset();
        auto result=storage_.settle_game(context_.username,context_.role_id,request);
        settled_=true;transmissions_.clear();phase_=RichonlineTerminalPhase::finished;
        return {RichonlineTerminalAbandonAction::loss_persisted,{},std::move(result),reason};
    } catch(const std::exception& error) {
        phase_=RichonlineTerminalPhase::recovery_required;
        return {RichonlineTerminalAbandonAction::recovery_required,{},{},
            std::string("richonline_terminal_abandon_persistence_failure: ")+error.what()+"; "+reason};
    }
}
RichonlineTerminalStep RichonlineTerminalCoordinator::bankrupt(std::span<const std::int8_t> actors) {
    if(phase_==RichonlineTerminalPhase::delivering)return {RichonlineTerminalAction::deliver,{}, {}};
    if(phase_==RichonlineTerminalPhase::finished)return {RichonlineTerminalAction::finished,{}, {}};
    if(phase_==RichonlineTerminalPhase::recovery_required)
        return {RichonlineTerminalAction::abort_live_game,{},"richonline_terminal_recovery_required"};
    if(phase_!=RichonlineTerminalPhase::playing)throw CodecError("richonline_terminal_bankruptcy_before_start");
    const auto decision=plan_richonline_terminal(context_.roster,actors,context_.rules);
    if(!decision.outcome) {
        std::vector<Bytes> messages;
        for(const auto actor:decision.newly_eliminated) {
            messages.push_back(richonline_bankruptcy_notice(context_.game_id,actor));
            messages.push_back(richonline_eliminate_actor(context_.game_id,actor));
        }
        context_.roster=decision.after;
        return {RichonlineTerminalAction::continue_play,std::move(messages),{}};
    }
    return deliver_result(decision);
}
RichonlineTerminalStep RichonlineTerminalCoordinator::month_limit() {
    if(phase_==RichonlineTerminalPhase::delivering)return {RichonlineTerminalAction::deliver,{}, {}};
    if(phase_==RichonlineTerminalPhase::finished)return {RichonlineTerminalAction::finished,{}, {}};
    if(phase_==RichonlineTerminalPhase::recovery_required)
        return {RichonlineTerminalAction::abort_live_game,{},"richonline_terminal_recovery_required"};
    if(phase_!=RichonlineTerminalPhase::playing)throw CodecError("richonline_terminal_month_limit_before_start");
    return deliver_result(plan_richonline_month_limit_terminal(context_.roster,context_.rules));
}
RichonlineTerminalStep RichonlineTerminalCoordinator::deliver_result(const RichonlineTerminalDecision& decision) {
    // Settlement must have a bounded outcome even when an NPC is waiting for it.
    // Return an explicit teardown action instead of an unfinishable wait phase.
    if(context_.result_byte18_evidence.empty()) {
        phase_=RichonlineTerminalPhase::recovery_required;
        return {RichonlineTerminalAction::abort_live_game,{},"richonline_terminal_unverified_401b_byte18"};
    }
    try {
        freeze_achievement();
        (void)commit_richonline_terminal(storage_,context_.username,context_.role_id,context_.settlement,
            context_.game_id,context_.room_id,decision,context_.rules);
        settled_=true;
        const auto pending=storage_.pending_game_settlements(context_.username,context_.role_id);
        const auto found=std::find_if(pending.begin(),pending.end(),[&](const auto& intent){
            return intent.operation_id==context_.settlement.operation_id;
        });
        if(found==pending.end())throw CodecError("richonline_terminal_committed_outbox_missing");
        transmissions_=recover_richonline_terminal_messages(*found,context_.settlement.match_id,context_.game_id);
        context_.roster=decision.after;phase_=RichonlineTerminalPhase::delivering;
        return {RichonlineTerminalAction::deliver,{}, {}};
    } catch(const std::exception& error) {
        phase_=RichonlineTerminalPhase::recovery_required;
        return {RichonlineTerminalAction::abort_live_game,{},std::string("richonline_terminal_persistence_failure: ")+error.what()};
    }
}
const RichonlineSettlementTransmission* RichonlineTerminalCoordinator::next_transmission() const noexcept {
    return phase_==RichonlineTerminalPhase::delivering && next_<transmissions_.size()?&transmissions_[next_]:nullptr;
}
std::vector<Bytes> RichonlineTerminalCoordinator::pending_game_messages() const {
    std::vector<Bytes> result;
    if(phase_!=RichonlineTerminalPhase::delivering)return result;
    for(auto i=next_;i<transmissions_.size();++i)
        if(transmissions_[i].transport==RichonlineSettlementTransport::game)
            result.push_back(transmissions_[i].game_plain);
    return result;
}
void RichonlineTerminalCoordinator::confirm_sent(std::uint32_t sequence) {
    const auto* current=next_transmission();
    if(!current || current->sequence!=sequence)throw CodecError("richonline_terminal_send_sequence");
    try {
        storage_.advance_game_settlement_outbox(context_.username,context_.role_id,context_.settlement.operation_id,sequence);
    } catch(...) {
        // The socket already accepted this packet. Retrying blindly could replay
        // 400E and decrement the client's active actor count for a second time.
        phase_=RichonlineTerminalPhase::recovery_required;throw;
    }
    ++next_;if(next_==transmissions_.size())phase_=RichonlineTerminalPhase::finished;
}
}
