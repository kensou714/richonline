#pragma once

// NEW C2S00A5 banana card. This component plans one shared-ground placement;
// the room executor owns the atomic inventory/ground commit.

#include "richonline_chance.hpp"
#include "richonline_npc_spawn.hpp"

namespace richnet {
enum class RichonlineGroundCard : std::uint16_t { supermine500=500, banana507 = 507, roadblock1043 = 1043 };

struct RichonlineGroundCardRequest {
    RichonlineGroundCard kind;
    std::uint16_t calendar;
    std::int8_t inventory_slot, inventory_bank;
    std::int16_t position;
};

// The session derives every field from authenticated turn and map authority.
// target_visible is deliberately explicit: click geometry is not an authority.
struct RichonlineGroundCardTurnContext {
    std::uint16_t game_id, calendar;
    std::int8_t active_actor, requesting_actor;
    bool roll_phase, requesting_actor_can_act;
    bool target_is_map_cell, target_is_walkable, target_visible, target_has_actor;
    std::int8_t target_static_type;
};

struct RichonlineGroundCardPlan {
    RichonlineGroundCardRequest request;
    RichonlineGroundSnapshot expected_ground;
    RichonlineGroundMap after_ground;
    RichonlineChanceInventory expected_inventory, after_inventory;
    // Exactly one S2C40F5. The player remains in the same roll action.
    Bytes response40f5;
};

RichonlineGroundCardRequest decode_richonline_ground_card165(View plain);
RichonlineGroundCardRequest decode_richonline_roadblock108(View plain);
RichonlineGroundCardRequest decode_richonline_supermine158(View plain);
Bytes encode_richonline_banana40f5(std::uint16_t game_id,
    const RichonlineGroundCardRequest& request);

// Throws CodecError on an unsupported or unauthorized placement. No input
// argument is mutable, so a failed plan cannot consume a card or occupy a cell.
RichonlineGroundCardPlan plan_richonline_banana_card(const RichonlineGroundCardRequest&,
    const RichonlineGroundCardTurnContext&, const RichonlineChanceInventory&,
    const RichonlineGroundSnapshot&);
} // namespace richnet
