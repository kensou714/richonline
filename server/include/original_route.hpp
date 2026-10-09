#pragma once

#include "original_map.hpp"
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <utility>

namespace richnet {
struct OriginalRouteRules {
    std::map<std::int16_t,std::int32_t> objects;
    bool teleports;
    std::optional<std::pair<std::int16_t,std::int16_t>> portals;
    std::optional<std::uint8_t> first_direction;
};
struct OriginalRouteRequest {
    std::int16_t start;
    std::uint8_t direction;
    std::uint8_t steps;
    OriginalRouteRules rules;
};
struct OriginalRouteStep {
    std::int16_t tile;
    std::uint8_t direction;
    bool operator==(const OriginalRouteStep&) const = default;
};
using OriginalRouteTrace = std::vector<OriginalRouteStep>;
using OriginalRouteRandom = std::function<std::uint32_t(std::uint32_t)>;

OriginalRouteTrace build_original_route(std::shared_ptr<const OriginalMapResources> map,
    const OriginalRouteRequest& request, const OriginalRouteRandom& random);
OriginalRouteTrace reconstruct_original_route(std::shared_ptr<const OriginalMapResources> map,
    const OriginalRouteRequest& request, std::span<const std::uint8_t> directions);
}
