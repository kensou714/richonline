#pragma once
#include "richonline_boss_cards.hpp"

namespace richnet {
enum class RichonlineCosmeticCard : std::uint16_t { love1127=154,starlight1131=168 };
struct RichonlineCosmeticCardRequest {
    RichonlineCosmeticCard kind;
    std::uint16_t calendar;
    std::int8_t slot,bank;
};
struct RichonlineCosmeticCardPlan {
    Bytes response;
    RichonlineBossCards::PreparedConsumption consumption;
};
RichonlineCosmeticCardRequest parse_richonline_cosmetic_card(View);
// Both NEW handlers enqueue their effect, consume one card, then restore local
// action controls. No movement, persistent combat modifier or C2S ACK follows.
RichonlineCosmeticCardPlan plan_richonline_cosmetic_card(std::uint16_t game_id,
    const RichonlineCosmeticCardRequest&,std::uint16_t current_calendar,const RichonlineBossCards&);
}
