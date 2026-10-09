#pragma once

#include "richonline_combat_world.hpp"

namespace richnet {
// A per-room server authorization rule. NEW165 does not transmit the camera
// viewport; Manhattan distance must not be described as recovered client FOV.
inline std::function<bool(std::uint8_t,std::int16_t,std::int16_t)>
make_richonline_ground_card_authority(const RichonlineRoadTopology& topology,
    std::size_t actor_count,const std::optional<RichonlineCombatRangePolicy>& policy) {
    if (!policy) return {};
    if (policy->name!="server_manhattan_tile_radius" || policy->manhattan_radius<1 ||
        policy->manhattan_radius>64)
        throw CodecError("richonline_ground_card_range_policy_invalid");
    if (actor_count==0 || actor_count>256)
        throw CodecError("richonline_ground_card_actor_count_invalid");
    std::vector<bool> roads;
    roads.reserve(topology.cells().size());
    for (const auto& cell:topology.cells()) roads.push_back(cell.walkable);
    return [roads=std::move(roads),width=topology.width(),actor_count,
        radius=policy->manhattan_radius](std::uint8_t actor,std::int16_t source,std::int16_t target) {
        if (actor>=actor_count || source<0 || target<0) return false;
        const auto from=static_cast<std::size_t>(source),to=static_cast<std::size_t>(target);
        if (from>=roads.size() || to>=roads.size() || !roads[from] || !roads[to]) return false;
        const auto x1=from%width,x2=to%width,y1=from/width,y2=to/width;
        const auto distance=(x1>x2 ? x1-x2 : x2-x1)+(y1>y2 ? y1-y2 : y2-y1);
        return distance<=radius;
    };
}
}
