#include "richonline_classic_terminal.hpp"
#include "lua_server.hpp"
#include <algorithm>
#include <set>

namespace richnet {
RichonlineClassicTerminal::RichonlineClassicTerminal(Storage& storage,RichonlineClassicTerminalContext context,
    std::shared_ptr<const RichonlineGameLedger> ledger)
    :storage_(storage),context_(std::move(context)),ledger_(std::move(ledger)) {
    const auto count=context_.participants.size();
    if(count<2 || count>4 || !ledger_ || ledger_->actor_count()!=count || context_.byte18.evidence.empty() ||
        context_.byte18.evidence.size()>1024 || context_.byte18.evidence.find('\0')!=std::string::npos ||
        context_.show_text_270 || context_.display.delay<std::chrono::milliseconds{4000})
        throw CodecError("richonline_classic_terminal_context_invalid");
    (void)richonline_lobby_game_finished(context_.room_id);
    std::set<std::int64_t> roles;std::set<std::string> operations;
    const auto& first=context_.participants.front().request;
    for(auto& participant:context_.participants) {
        auto& request=participant.request;
        if(participant.username.empty() || !roles.insert(participant.role_id).second || request.operation_id.empty() ||
            !operations.insert(request.operation_id).second || request.match_id.empty() || request.stage_key.empty() ||
            request.match_id!=first.match_id || request.stage_key!=first.stage_key || request.delivery || request.achievement ||
            ((request.pawn_gold==0)==request.pledge_charge_operation.has_value()))
            throw CodecError("richonline_classic_terminal_identity_invalid");
        if(request.policy.provenance.empty() || request.policy.provenance.find('\0')!=std::string::npos)
            throw CodecError("richonline_classic_terminal_reward_policy_missing");
        request.policy.provenance+="; native-classic-last-survivor-v1; "+context_.byte18.evidence;
        if(request.policy.provenance.size()>1024)throw CodecError("richonline_classic_terminal_reward_policy_invalid");
        display_.emplace_back(context_.display);
    }
    cursors_.resize(count);
}
void RichonlineClassicTerminal::validate_identity(std::uint16_t game,std::uint32_t room,std::size_t count,
    std::uint32_t pawn_gold,const RichonlineGameLedger* ledger) const {
    if(game!=context_.game_id || room!=context_.room_id || count!=context_.participants.size() || ledger!=ledger_.get())
        throw CodecError("richonline_classic_terminal_session_mismatch");
    for(const auto& participant:context_.participants) if(participant.request.pawn_gold!=pawn_gold)
        throw CodecError("richonline_classic_terminal_pledge_mismatch");
}
void RichonlineClassicTerminal::validate_last_survivor(std::span<const std::uint8_t> active) const {
    if(committed_ || recovery_required_ || active.size()!=context_.participants.size() ||
        std::ranges::any_of(active,[](auto value){return value>1;}) || std::ranges::count(active,std::uint8_t{1})!=1)
        throw CodecError("richonline_classic_terminal_survivor_invalid");
}
std::vector<Bytes> RichonlineClassicTerminal::finish(std::span<const std::uint8_t> active,std::uint8_t bankrupt) {
    validate_last_survivor(active);
    if(bankrupt>=active.size() || active[bankrupt])throw CodecError("richonline_classic_terminal_bankrupt_invalid");
    const auto winner=static_cast<std::int8_t>(std::ranges::find(active,std::uint8_t{1})-active.begin());
    if(context_.script) {
        auto expected_actors=LuaValue::array();
        for(std::size_t slot=0;slot<active.size();++slot)expected_actors.push_back({
            {"slot",slot},{"outcome",active[slot]?"win":"loss"},
            {"rank",active[slot]?context_.win_rank:context_.loss_rank}});
        const auto result=context_.script->call("game.classic_settlement",{
            {"active",std::vector<std::uint8_t>(active.begin(),active.end())},
            {"win_rank",context_.win_rank},{"loss_rank",context_.loss_rank}});
        const LuaValue expected{{"winner",winner},{"actors",expected_actors}};
        if(result!=expected || !result.at("winner").is_number_integer())
            throw CodecError("lua_classic_settlement_invalid");
        for(const auto& actor:result.at("actors"))
            if(!actor.at("slot").is_number_integer() || !actor.at("rank").is_number_integer())
                throw CodecError("lua_classic_settlement_integer_required");
    }
    auto participants=context_.participants;
    std::vector<std::string> operations;
    for(const auto& participant:participants)operations.push_back(participant.request.operation_id);
    for(std::size_t slot=0;slot<participants.size();++slot) {
        auto& request=participants[slot].request;
        request.outcome=slot==static_cast<std::size_t>(winner)?GameOutcome::win:GameOutcome::loss;
        const auto income=ledger_->income_snapshot(static_cast<std::uint8_t>(slot));
        request.achievement=GameSettlementAchievement{RichonlineAchievement::cash_earned,income.earned_cash,
            richonline_cash_earned_policy,income.ledger_revision};
        request.delivery=GameSettlementDelivery{context_.game_id,context_.room_id,static_cast<std::int8_t>(slot),
            request.outcome==GameOutcome::win?context_.win_rank:context_.loss_rank,context_.byte18.value,
            context_.show_text_270,{static_cast<std::int8_t>(bankrupt)},3,operations,winner};
    }
    // DB失败会整体回滚。其后的失败保留committed_，不得把已结算对局改记为逃跑或重发奖励。
    const auto receipts=storage_.settle_game_match(participants);
    committed_=true;
    try {
        if(std::ranges::any_of(receipts,[](const auto& result){return result.replayed;}))
            throw CodecError("richonline_classic_terminal_replay_requires_reconciliation");
        std::vector<RichonlineSettledActor> actors;
        for(std::size_t slot=0;slot<receipts.size();++slot) {
            const auto& request=participants[slot].request;
            actors.push_back({static_cast<std::int8_t>(slot),request.delivery->rank_image_index,request.outcome,false,
                context_.byte18.value,receipts[slot]});
        }
        const std::array eliminated{static_cast<std::int8_t>(bankrupt)};
        messages_=plan_richonline_settlement(context_.game_id,eliminated,actors,context_.show_text_270);
        return messages_;
    } catch(...) {recovery_required_=true;throw;}
}
void RichonlineClassicTerminal::sent(std::uint8_t recipient,View plain) {
    if(!committed_)return;
    if(recipient>=cursors_.size() || recovery_required_)throw CodecError("richonline_classic_terminal_send_invalid");
    // 最终租金4013/嫁祸40C6仍在结算前缀中，由原业务处理，不占结算outbox游标。
    if(plain.size()<2)throw CodecError("richonline_classic_terminal_send_invalid");
    const auto opcode=read_le(plain.first(2));
    if(opcode!=0x400d && opcode!=0x400e && opcode!=0x401b && opcode!=0x400f)return;
    auto& cursor=cursors_[recipient];
    if(cursor>=messages_.size() || !std::ranges::equal(plain,messages_[cursor]))
        throw CodecError("richonline_classic_terminal_send_sequence");
    const auto& participant=context_.participants[recipient];
    try {
        storage_.advance_game_settlement_outbox(participant.username,participant.role_id,
            participant.request.operation_id,static_cast<std::uint32_t>(cursor));
        ++cursor;
        if(cursor==messages_.size())display_[recipient].game_frames_sent();
    } catch(...) {recovery_required_=true;throw;}
}
bool RichonlineClassicTerminal::game_finished(std::uint8_t recipient) const {
    return committed_ && !recovery_required_ && recipient<cursors_.size() &&
        cursors_[recipient]==messages_.size() && display_[recipient].ready();
}
void RichonlineClassicTerminal::lobby_sent(std::uint8_t recipient,const Frame& frame) {
    if(!game_finished(recipient))return;
    const auto expected=richonline_lobby_game_finished(context_.room_id);
    if(frame.wire_type!=expected.wire_type || frame.payload!=expected.payload)return;
    const auto& participant=context_.participants[recipient];
    try {
        storage_.advance_game_settlement_outbox(participant.username,participant.role_id,
            participant.request.operation_id,static_cast<std::uint32_t>(cursors_[recipient]));
        ++cursors_[recipient];
    } catch(...) {recovery_required_=true;throw;}
}
}
