#pragma once

#include "game_settlement.hpp"
#include "richonline_game_end.hpp"
#include "richonline_boss_stage.hpp"

namespace richnet {
// BossWar provides first/repeat victory rewards only. Loss/draw economics,
// pledge return and bonuses must be an explicit server rule with provenance.
struct RichonlineBossSettlementRules {
    std::string provenance;
    bool return_winning_pledge;
    std::uint32_t first_win_bonus;
    std::uint32_t repeat_win_bonus;
    GameSettlementReward loss;
    GameSettlementReward draw;
};
GameSettlementPolicy richonline_boss_settlement_policy(const RichonlineBossStage& stage,
    const std::array<std::uint32_t,21>& levels,const RichonlineBossSettlementRules& rules);

struct RichonlineSettledActor {
    std::int8_t slot;
    std::int8_t rank_image_index;
    GameOutcome outcome;
    bool escaped;
    // Not guessed: a caller must supply an independently verified value.
    std::uint8_t opaque_18;
    GameSettlementResult persisted;
};

// Build only after SQLite commits. Bankruptcy/elimination notifications must
// precede result records, and all records must precede the result UI trigger.
// The caller owns victory rules and delays; this function adds no cash delta.
std::vector<Bytes> plan_richonline_settlement(std::uint16_t game_id,
    std::span<const std::int8_t> bankrupt_slots,
    std::span<const RichonlineSettledActor> actors,bool show_text_270);

// Lobby wire58 is distinct from its internal callback18 and game local6021.
// Send after the game result sequence has been delivered and the caller's
// result-display policy has completed. It preserves the room and clears ready.
Frame richonline_lobby_game_finished(std::uint32_t room_id);
}
