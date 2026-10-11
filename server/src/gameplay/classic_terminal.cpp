#include "richonline_classic_terminal.hpp"
#include "lua_server.hpp"
#include <algorithm>
#include <set>
#include <limits>

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
        if((request.policy.provenance+"; native-classic-last-survivor-v1; "+context_.byte18.evidence).size()>1024)
            throw CodecError("richonline_classic_terminal_reward_policy_invalid");
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
    std::vector<GameOutcome> outcomes;
    std::vector<std::int8_t> ranks;
    for(const auto value:active) {
        outcomes.push_back(value?GameOutcome::win:GameOutcome::loss);
        ranks.push_back(value?context_.win_rank:context_.loss_rank);
    }
    return commit_result(outcomes,ranks,{context_.game_id,context_.room_id,0,0,context_.byte18.value,
        context_.show_text_270,{static_cast<std::int8_t>(bankrupt)},3,{},winner},"last-survivor-v1");
}
void RichonlineClassicTerminal::validate_month_limit(std::span<const std::uint8_t> active) const {
    if(committed_ || recovery_required_ || !context_.asset_rank_images || active.size()!=context_.participants.size() ||
        std::ranges::any_of(active,[](auto value){return value>1;}) || std::ranges::count(active,std::uint8_t{1})<2)
        throw CodecError("richonline_classic_terminal_month_context_invalid");
}
std::vector<Bytes> RichonlineClassicTerminal::finish_month_limit(std::span<const std::uint8_t> active,
    std::span<const RichonlineClassicAssets> assets,const std::string& evidence) {
    validate_month_limit(active);
    if(assets.size()!=active.size() || evidence.empty() || evidence.size()>512 || evidence.find('\0')!=std::string::npos)
        throw CodecError("richonline_classic_terminal_assets_invalid");
    std::vector<std::uint64_t> totals;
    auto players=LuaValue::array();
    constexpr auto maximum=static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    std::uint64_t highest=0;
    for(std::size_t slot=0;slot<assets.size();++slot) {
        const auto& value=assets[slot];
        const auto funds=ledger_->snapshot(static_cast<std::uint8_t>(slot)).funds;
        if(!funds.deposit || funds.cash!=value.cash || *funds.deposit!=value.deposit)
            throw CodecError("richonline_classic_terminal_asset_funds_stale");
        std::uint64_t total=0;
        for(const auto part:{std::uint64_t{value.cash},std::uint64_t{value.deposit},value.stocks,value.property}) {
            if(part>maximum-total)throw CodecError("richonline_classic_terminal_asset_overflow");
            total+=part;
        }
        totals.push_back(total);
        if(active[slot])highest=std::max(highest,total);
        players.push_back({{"active",active[slot]!=0},{"cash",value.cash},{"deposit",value.deposit},
            {"stocks",value.stocks},{"property",value.property}});
    }
    std::vector<GameOutcome> outcomes;
    std::vector<std::int8_t> ranks,winners;
    auto expected_actors=LuaValue::array();
    for(std::size_t slot=0;slot<assets.size();++slot) {
        const bool winner=active[slot] && totals[slot]==highest;
        if(winner)winners.push_back(static_cast<std::int8_t>(slot));
        std::size_t rank=1;
        for(std::size_t other=0;other<assets.size();++other)
            if(active[other] && (!active[slot] || totals[other]>totals[slot]))++rank;
        // 破产者已退出排名竞争；仍在最后的全员表中，排在所有存活者之后。
        ranks.push_back(context_.asset_rank_images->at(rank-1));
        outcomes.push_back(winner?GameOutcome::win:GameOutcome::loss);
        expected_actors.push_back({{"slot",slot},{"outcome",winner?"win":"loss"},
            {"rank",ranks.back()},{"place",rank},{"assets",totals[slot]}});
    }
    if(context_.script) {
        const auto result=context_.script->call("game.classic_settlement",{{"reason","month_limit"},
            {"players",players},{"rank_images",*context_.asset_rank_images}});
        const LuaValue expected{{"winners",winners},{"actors",expected_actors}};
        if(result!=expected)throw CodecError("lua_classic_asset_settlement_invalid");
        for(const auto& actor:result.at("actors"))
            for(const auto* key:{"slot","rank","place","assets"})
                if(!actor.at(key).is_number_integer())throw CodecError("lua_classic_asset_settlement_integer_required");
        for(const auto& slot:result.at("winners"))
            if(!slot.is_number_integer())throw CodecError("lua_classic_asset_settlement_integer_required");
    }
    GameSettlementDelivery delivery{context_.game_id,context_.room_id,0,0,context_.byte18.value,false,{},4};
    delivery.winner_slots=std::move(winners);delivery.asset_totals=std::move(totals);
    delivery.active_slots.assign(active.begin(),active.end());
    return commit_result(outcomes,ranks,std::move(delivery),"user-total-assets-tied-first-v1; "+evidence);
}
std::vector<Bytes> RichonlineClassicTerminal::commit_result(std::span<const GameOutcome> outcomes,
    std::span<const std::int8_t> ranks,GameSettlementDelivery delivery,const std::string& evidence) {
    auto participants=context_.participants;
    std::vector<std::string> operations;
    for(const auto& participant:participants)operations.push_back(participant.request.operation_id);
    for(std::size_t slot=0;slot<participants.size();++slot) {
        auto& request=participants[slot].request;
        request.outcome=outcomes[slot];
        // 保留旧唯一存活者请求的规范文本，避免升级后同一操作键的重放失配。
        request.policy.provenance+=delivery.message_version==3 ?
            "; native-classic-last-survivor-v1; "+context_.byte18.evidence :
            "; native-classic-terminal-v1; "+context_.byte18.evidence+"; "+evidence;
        if(request.policy.provenance.size()>1024)throw CodecError("richonline_classic_terminal_reward_policy_invalid");
        const auto income=ledger_->income_snapshot(static_cast<std::uint8_t>(slot));
        request.achievement=GameSettlementAchievement{RichonlineAchievement::cash_earned,income.earned_cash,
            richonline_cash_earned_policy,income.ledger_revision};
        request.delivery=delivery;
        request.delivery->human_slot=static_cast<std::int8_t>(slot);
        request.delivery->rank_image_index=ranks[slot];
        request.delivery->roster_operations=operations;
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
        messages_=plan_richonline_settlement(context_.game_id,delivery.bankrupt_slots,actors,delivery.show_text_270);
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
