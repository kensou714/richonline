#pragma once

#include "richonline_combat_world.hpp"

namespace richnet {
// Ground-card requests carry a map cell, not the client's camera viewport.
// Keep legacy configuration readable without imposing the BOSS attack radius.
inline std::function<bool(std::uint8_t,std::int16_t,std::int16_t)>
make_richonline_ground_card_authority(const RichonlineRoadTopology& topology,
    std::size_t actor_count,const std::optional<RichonlineCombatRangePolicy>& policy) {
    if (!policy) return {};
    const bool radial=policy->name=="server_manhattan_tile_radius" &&
        policy->manhattan_radius>=1 && policy->manhattan_radius<=64;
    const bool viewport=policy->name=="server_boss_centered_viewport" &&
        policy->viewport_width>=64 && policy->viewport_width<=4096 &&
        policy->viewport_height>=48 && policy->viewport_height<=4096 &&
        policy->projectile_candidates==RichonlineProjectileCandidates::road_tiles;
    if (!radial && !viewport)
        throw CodecError("richonline_ground_card_range_policy_invalid");
    if (actor_count==0 || actor_count>256)
        throw CodecError("richonline_ground_card_actor_count_invalid");
    std::vector<bool> roads;
    roads.reserve(topology.cells().size());
    for (const auto& cell:topology.cells()) roads.push_back(cell.walkable);
    return [roads=std::move(roads),actor_count](std::uint8_t actor,std::int16_t source,std::int16_t target) {
        if (actor>=actor_count || source<0 || target<0) return false;
        const auto from=static_cast<std::size_t>(source),to=static_cast<std::size_t>(target);
        // Each card planner checks roads, occupied cells and static exclusions.
        // Fire can select a non-road center and affect surrounding road cells.
        return from<roads.size() && to<roads.size() && roads[from];
    };
}
}
