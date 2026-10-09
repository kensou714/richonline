#pragma once
#include "richonline_boss_cards.hpp"

namespace richnet {
struct RichonlineFixedStepCardRequest {
    std::uint16_t opcode,calendar;
    std::int8_t slot,bank;
};
struct RichonlineFixedStepCardPlan {
    Bytes confirmation;
    RichonlineBossCards::PreparedConsumption consumption;
    std::uint8_t steps;
};
RichonlineFixedStepCardRequest parse_richonline_fixed_step_card(View);
// Like1038, send confirmation followed by the normal authoritative movement
// projection. Confirmation alone neither moves the actor nor restores controls.
RichonlineFixedStepCardPlan plan_richonline_fixed_step_card(std::uint16_t game_id,
    const RichonlineFixedStepCardRequest&,std::uint16_t current_calendar,const RichonlineBossCards&);
}
