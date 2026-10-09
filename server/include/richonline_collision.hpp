#pragma once
#include "richonline_chance.hpp"
#include <optional>
#include <span>
#include <vector>

namespace richnet {
struct RichonlineCollisionActor {
    std::uint8_t slot;
    std::int16_t position;
    bool active,synthetic;
    // Exact NEW actor+1497 != -1 gate; not guessed from a different status.
    bool excluded1497;
    std::optional<std::int8_t> possession;
    RichonlineChanceInventory inventory;
    bool operator==(const RichonlineCollisionActor&) const = default;
};
struct RichonlineCollisionTransfer {
    std::uint8_t source_actor,target_actor,source_slot;
    std::int16_t card_id;
};
struct RichonlineCollisionPlan {
    std::vector<RichonlineCollisionActor> before,after;
    std::vector<RichonlineCollisionTransfer> transfers;
    // NEW 7CB050 returns before junction when game+83830 != -1 or mode4
    // synthetic current actor. Otherwise its final junction logic still runs.
    bool evaluate_junction;
};
// Invoke once in final phase6 AFTER ground, static and property effects.
// 4013 already starts this client-local chain; no invented collision packet
// is sent. The resulting inventory deltas mirror local6061 consumption/add.
RichonlineCollisionPlan plan_richonline_collision(std::uint8_t active_actor,
    std::uint32_t game_mode,bool phase_suppressed83830,std::span<const RichonlineCollisionActor>,
    const RichonlineChanceResources&,std::string_view map);
void commit_richonline_collision(std::span<RichonlineCollisionActor>,const RichonlineCollisionPlan&);
// Admission proof for the present one-human/one-synthetic BOSS runtime. A god
// picked up earlier in this landing cannot enable theft across this pair.
bool richonline_boss_collision_allows_shared_landing(std::uint32_t game_mode,
    std::uint8_t active_actor,std::span<const RichonlineCollisionActor>);
}
