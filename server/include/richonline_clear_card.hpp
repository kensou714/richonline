#pragma once

#include "richonline_chance.hpp"
#include "richonline_npc_spawn.hpp"

namespace richnet {
struct RichonlineClearCardRequest {
    std::uint16_t calendar;
    std::int8_t inventory_slot, inventory_bank;
};
struct RichonlineClearCardContext {
    std::uint16_t game_id, calendar;
    std::int8_t active_actor, requesting_actor;
    bool roll_phase, requesting_actor_can_act;
};
struct RichonlineClearCardPlan {
    RichonlineClearCardRequest request;
    RichonlineGroundSnapshot expected_ground;
    RichonlineGroundMap after_ground;
    RichonlineChanceInventory expected_inventory, after_inventory;
    Bytes response40f0;
};

RichonlineClearCardRequest decode_richonline_clear_card160(View);
Bytes encode_richonline_clear40f0(std::uint16_t game_id, const RichonlineClearCardRequest&);
// The room commits the inventory and shared ground together before sending.
// NPC replenishment follows this commit through the map's existing policy.
RichonlineClearCardPlan plan_richonline_clear_card(const RichonlineClearCardRequest&,
    const RichonlineClearCardContext&, const RichonlineChanceInventory&,
    const RichonlineGroundSnapshot&);
} // namespace richnet
