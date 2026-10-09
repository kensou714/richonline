#pragma once

#include "richonline_map_package.hpp"

namespace richnet {
// NEW 4019 replaces only the first four six-byte slots of an existing actor.
struct RichonlineInventoryPrefix4019 {
    std::uint16_t game_id;
    std::int16_t actor;
    std::array<RichonlineChanceCardSlot,4> slots;
    std::array<std::array<std::uint8_t,2>,4> slot_tail;
    bool operator==(const RichonlineInventoryPrefix4019&) const = default;
};
Bytes encode_richonline_inventory_prefix4019(const RichonlineInventoryPrefix4019& value,std::size_t actor_count);
RichonlineInventoryPrefix4019 decode_richonline_inventory_prefix4019(View plain,std::size_t actor_count);
struct RichonlineOpeningHandPlan {
    std::array<RichonlineChanceInventory,2> inventories;
    std::array<Bytes,2> synchronization;
};
// Pure preparation for a new two-actor BOSS game. The session owns once-only commit/emission.
RichonlineOpeningHandPlan prepare_richonline_opening_hand(std::uint16_t game_id,
    const RichonlineMapOpeningHand& configured,const RichonlineChanceResources& resources);
}
