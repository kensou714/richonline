#include "richonline_terminal.hpp"
#include <algorithm>
#include <utility>

namespace richnet {
RichonlineResultByte18Compatibility richonline_boss_result_byte18_compatibility(
    std::string_view client_sha256,std::uint32_t mode) {
    const bool original=client_sha256=="cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77";
    const bool graphics=client_sha256=="a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2";
    if((!original && !graphics) || mode!=3)
        throw CodecError("richonline_result_byte18_compatibility_scope_mismatch");
    std::string evidence="NEW cb35f69f normal BOSS result: roster 7BAD80 zero initializer; 65E460 stores byte18; "
        "717C70/71E040 do not read roster+152; settlement/RESULT_BYTE18_AUDIT.md";
    if(graphics) evidence+="; a23410e7 inherits cb35f69f audit: exact 3-byte D3D flags-only chain; "
        "settlement/graphics-byte18-chain.json";
    return {0,std::move(evidence)};
}
namespace {
void rules_valid(const RichonlineTerminalRules& rules) {
    if(rules.provenance.empty() || rules.provenance.size()>512 || rules.provenance.find('\0')!=std::string::npos)
        throw CodecError("richonline_terminal_rules_missing");
    if(rules.simultaneous_defeat!=RichonlineSimultaneousDefeat::human_loss &&
        rules.simultaneous_defeat!=RichonlineSimultaneousDefeat::draw)
        throw CodecError("richonline_terminal_simultaneous_rule_invalid");
}
std::array<bool,8> roster(const RichonlineTerminalSnapshot& snapshot) {
    if(snapshot.mode!=3 || snapshot.human_slot<0 || snapshot.human_slot>=8 ||
        snapshot.boss_slots.empty() || snapshot.boss_slots.size()>7)
        throw CodecError("richonline_terminal_roster_invalid");
    std::array<bool,8> result{};result[static_cast<std::size_t>(snapshot.human_slot)]=true;
    for(const auto slot:snapshot.boss_slots) {
        if(slot<0 || slot>=8 || result[static_cast<std::size_t>(slot)])throw CodecError("richonline_terminal_roster_invalid");
        result[static_cast<std::size_t>(slot)]=true;
    }
    return result;
}
}
RichonlineTerminalDecision plan_richonline_terminal(const RichonlineTerminalSnapshot& snapshot,
    std::span<const std::int8_t> bankrupt,const RichonlineTerminalRules& rules) {
    rules_valid(rules);const auto registered=roster(snapshot);std::array<bool,8> dead{};
    for(const auto slot:snapshot.eliminated_slots) {
        if(slot<0 || slot>=8 || !registered[static_cast<std::size_t>(slot)] || dead[static_cast<std::size_t>(slot)])
            throw CodecError("richonline_terminal_eliminated_invalid");
        dead[static_cast<std::size_t>(slot)]=true;
    }
    RichonlineTerminalDecision result{{},snapshot,{}};std::array<bool,8> event{};
    for(const auto slot:bankrupt) {
        if(slot<0 || slot>=8 || !registered[static_cast<std::size_t>(slot)] || event[static_cast<std::size_t>(slot)])
            throw CodecError("richonline_terminal_bankrupt_invalid");
        event[static_cast<std::size_t>(slot)]=true;
        if(!dead[static_cast<std::size_t>(slot)]) {
            dead[static_cast<std::size_t>(slot)]=true;
            result.after.eliminated_slots.push_back(slot);result.newly_eliminated.push_back(slot);
        }
    }
    const auto bosses_dead=std::all_of(snapshot.boss_slots.begin(),snapshot.boss_slots.end(),[&](auto slot){return dead[static_cast<std::size_t>(slot)];});
    const auto human_dead=dead[static_cast<std::size_t>(snapshot.human_slot)];
    if(human_dead)result.outcome=bosses_dead && rules.simultaneous_defeat==RichonlineSimultaneousDefeat::draw?GameOutcome::draw:GameOutcome::loss;
    else if(bosses_dead)result.outcome=GameOutcome::win;
    return result;
}
RichonlineTerminalDecision plan_richonline_month_limit_terminal(
    const RichonlineTerminalSnapshot& snapshot,const RichonlineTerminalRules& rules) {
    auto result=plan_richonline_terminal(snapshot,{},rules);
    if(result.outcome) throw CodecError("richonline_month_limit_roster_already_terminal");
    result.outcome=GameOutcome::loss;
    result.cause=RichonlineTerminalCause::month_limit;
    return result;
}
GameSettlementResult commit_richonline_terminal(Storage& storage,const std::string& username,std::int64_t role,
    GameSettlementRequest request,std::uint16_t game_id,std::uint32_t room_id,
    const RichonlineTerminalDecision& decision,const RichonlineTerminalRules& rules) {
    rules_valid(rules);
    if(decision.cause!=RichonlineTerminalCause::bankruptcy && decision.cause!=RichonlineTerminalCause::month_limit)
        throw CodecError("richonline_terminal_cause_invalid");
    if(decision.cause==RichonlineTerminalCause::month_limit && !decision.newly_eliminated.empty())
        throw CodecError("richonline_month_limit_elimination_invalid");
    const auto verified=decision.cause==RichonlineTerminalCause::month_limit ?
        plan_richonline_month_limit_terminal(decision.after,rules) : plan_richonline_terminal(decision.after,{},rules);
    if(!decision.outcome || decision.outcome!=verified.outcome)throw CodecError("richonline_terminal_not_complete");
    for(const auto slot:decision.newly_eliminated)
        if(std::find(decision.after.eliminated_slots.begin(),decision.after.eliminated_slots.end(),slot)==decision.after.eliminated_slots.end())
            throw CodecError("richonline_terminal_eliminated_invalid");
    request.outcome=*decision.outcome;
    const auto rank=request.outcome==GameOutcome::win?rules.win_rank:request.outcome==GameOutcome::loss?rules.loss_rank:rules.draw_rank;
    request.delivery=GameSettlementDelivery{game_id,room_id,decision.after.human_slot,rank,rules.result_opaque_18,
        rules.show_text_270,decision.newly_eliminated};
    request.policy.provenance+="; terminal "+rules.provenance;
    if(decision.cause==RichonlineTerminalCause::month_limit)
        request.policy.provenance+="; native-unfinished-boss-month-limit-loss-v1";
    return storage.settle_game(username,role,request);
}
std::vector<RichonlineSettlementTransmission> recover_richonline_terminal_messages(
    const GameSettlementOutbox& outbox,const std::string& live_match,std::uint16_t live_game) {
    if(outbox.match_id!=live_match || outbox.delivery.game_id!=live_game)
        throw CodecError("richonline_terminal_recovery_session_mismatch");
    const auto& delivery=outbox.delivery;
    const std::array actor{RichonlineSettledActor{delivery.human_slot,delivery.rank_image_index,outbox.outcome,false,
        delivery.opaque_18,outbox.result}};
    const auto game=plan_richonline_settlement(delivery.game_id,delivery.bankrupt_slots,actor,delivery.show_text_270);
    if(outbox.next_message>game.size())throw CodecError("richonline_terminal_outbox_cursor_invalid");
    std::vector<RichonlineSettlementTransmission> messages;
    for(std::size_t i=outbox.next_message;i<game.size();++i)
        messages.push_back({RichonlineSettlementTransport::game,static_cast<std::uint32_t>(i),game[i],{}});
    messages.push_back({RichonlineSettlementTransport::lobby,static_cast<std::uint32_t>(game.size()),{},richonline_lobby_game_finished(delivery.room_id)});
    return messages;
}
}
