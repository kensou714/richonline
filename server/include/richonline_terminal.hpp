#pragma once

#include "richonline_settlement.hpp"
#include "storage.hpp"
#include <string_view>

namespace richnet {
struct RichonlineResultByte18Compatibility {
    std::uint8_t value;
    std::string evidence;
};
// For the audited NEW binary's normal BOSS result path only. The client stores
// this byte but its roster result readers do not consume it. Preserve the
// client's constructor value; do not infer an original-server business meaning.
RichonlineResultByte18Compatibility richonline_boss_result_byte18_compatibility(
    std::string_view client_sha256,std::uint32_t mode);
enum class RichonlineSimultaneousDefeat { human_loss, draw };
struct RichonlineTerminalRules {
    std::string provenance;
    RichonlineSimultaneousDefeat simultaneous_defeat;
    std::int8_t win_rank,loss_rank,draw_rank;
    std::uint8_t result_opaque_18;
    bool show_text_270;
};
struct RichonlineTerminalSnapshot {
    std::uint32_t mode;
    std::int8_t human_slot;
    std::vector<std::int8_t> boss_slots;
    std::vector<std::int8_t> eliminated_slots;
};
enum class RichonlineTerminalCause { bankruptcy, month_limit };
struct RichonlineTerminalDecision {
    std::optional<GameOutcome> outcome;
    RichonlineTerminalSnapshot after;
    std::vector<std::int8_t> newly_eliminated;
    RichonlineTerminalCause cause=RichonlineTerminalCause::bankruptcy;
};
RichonlineTerminalDecision plan_richonline_terminal(const RichonlineTerminalSnapshot& snapshot,
    std::span<const std::int8_t> bankrupt_actors,const RichonlineTerminalRules& rules);
// Simulator policy: an unfinished BOSS challenge loses on expiry. No living
// actor is eliminated, and this is not an inferred original-server reward rule.
RichonlineTerminalDecision plan_richonline_month_limit_terminal(
    const RichonlineTerminalSnapshot& snapshot,const RichonlineTerminalRules& rules);

// Does not mutate combat balances. The request's outcome/delivery are replaced
// by the validated decision; all rewards and any real pledge remain explicit.
GameSettlementResult commit_richonline_terminal(Storage& storage,const std::string& username,std::int64_t role,
    GameSettlementRequest request,std::uint16_t game_id,std::uint32_t room_id,
    const RichonlineTerminalDecision& decision,const RichonlineTerminalRules& rules);

enum class RichonlineSettlementTransport { game,lobby };
struct RichonlineSettlementTransmission {
    RichonlineSettlementTransport transport;
    std::uint32_t sequence;
    // Game: inner plaintext; lobby: Frame wire type and payload.
    Bytes game_plain;
    std::optional<Frame> lobby;
};
// A recovered intent may only be sent to this same live match/game identity.
// Call advance_game_settlement_outbox only AFTER a successful whole send.
// Original protocol has no settlement message ACK: a crash between send and
// checkpoint can require client resynchronization rather than blind replay.
std::vector<RichonlineSettlementTransmission> recover_richonline_terminal_messages(
    const GameSettlementOutbox& outbox,const std::string& live_match_id,std::uint16_t live_game_id);
}
