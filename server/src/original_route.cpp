#include "original_route.hpp"
#include <set>

namespace richnet {
namespace {
constexpr std::size_t maximum_steps = 36;
constexpr std::size_t maximum_extensions = 18;
std::uint8_t opposite(std::uint8_t direction) { return static_cast<std::uint8_t>((direction+2U)&3U); }

class Geometry final {
public:
    Geometry(const std::shared_ptr<const OriginalMapResources>& map, const OriginalRouteRequest& request)
        : rules(request.rules) {
        if (!map) throw CodecError("original_route_map_missing");
        width = map->emp.width; height = map->emp.height;
        const auto cells = static_cast<std::uint64_t>(width)*height;
        if (width == 0 || height == 0 || cells > 32768) throw CodecError("original_route_map_dimensions_invalid");
        for (const auto& road : map->roads) {
            if (road.tile < 0 || static_cast<std::uint32_t>(road.tile) >= cells || !roads.emplace(road.tile,road.type).second)
                throw CodecError("original_route_road_invalid");
        }
        if (!roads.contains(request.start)) throw CodecError("original_route_start_invalid");
        if (request.direction > 3 || (rules.first_direction && *rules.first_direction > 3))
            throw CodecError("original_route_direction_invalid");
        if (request.steps == 0 || request.steps > 18) throw CodecError("original_route_steps_invalid");
        for (const auto& [tile,kind] : rules.objects) {
            static_cast<void>(kind);
            if (!roads.contains(tile)) throw CodecError("original_route_object_tile_invalid");
        }
        if (rules.portals) {
            const auto [a,b] = *rules.portals;
            if (a == b || !roads.contains(a) || !roads.contains(b) || roads.at(a) != 61 || roads.at(b) != 61)
                throw CodecError("original_route_portals_invalid");
        }
    }
    std::int32_t object(std::int16_t tile) const {
        const auto found = rules.objects.find(tile);
        return found == rules.objects.end() ? -1 : found->second;
    }
    std::int16_t origin(std::int16_t tile, std::size_t step) const {
        if (step == 0 || !rules.teleports || roads.at(tile) != 61) return tile;
        if (!rules.portals) throw CodecError("original_route_portals_missing");
        const auto [a,b] = *rules.portals;
        if (tile == a) return b;
        if (tile == b) return a;
        throw CodecError("original_route_portal_unpaired");
    }
    std::optional<std::int16_t> neighbor(std::int16_t tile, std::uint8_t direction) const {
        auto x = tile%static_cast<std::int32_t>(width), y = tile/static_cast<std::int32_t>(width);
        switch (direction) {
            case 0: ++y; break;
            case 1: --x; break;
            case 2: --y; break;
            case 3: ++x; break;
            default: throw CodecError("original_route_direction_invalid");
        }
        if (x < 0 || y < 0 || x >= static_cast<std::int32_t>(width) || y >= static_cast<std::int32_t>(height)) return std::nullopt;
        const auto id = static_cast<std::int16_t>(y*static_cast<std::int32_t>(width)+x);
        if (!roads.contains(id)) return std::nullopt;
        return id;
    }
private:
    const OriginalRouteRules& rules;
    std::uint32_t width, height;
    std::map<std::int16_t,std::int8_t> roads;
};

OriginalRouteStep choose_step(const Geometry& geometry, std::int16_t origin,
    std::uint8_t heading, std::optional<std::uint8_t> forced, const OriginalRouteRandom& random) {
    std::set<std::uint8_t> blocked;
    for (;;) {
        std::vector<OriginalRouteStep> choices;
        if (forced) {
            const auto next = geometry.neighbor(origin,*forced);
            if (!next) throw CodecError("original_route_first_direction_unavailable");
            choices.push_back({*next,*forced});
            forced.reset();
        } else {
            for (std::uint8_t direction = 0; direction < 4; ++direction) {
                if (direction == opposite(heading) || blocked.contains(direction)) continue;
                const auto next = geometry.neighbor(origin,direction);
                if (next) choices.push_back({*next,direction});
            }
            if (choices.empty() && !blocked.contains(opposite(heading))) {
                const auto next = geometry.neighbor(origin,opposite(heading));
                if (next) choices.push_back({*next,opposite(heading)});
            }
        }
        if (choices.empty()) throw CodecError("original_route_trapped");
        const auto count = static_cast<std::uint32_t>(choices.size());
        const auto index = count == 1 ? 0U : random(count);
        if (index >= count) throw CodecError("original_route_random_out_of_range");
        const auto candidate = choices[index];
        if (geometry.object(candidate.tile) != 29) return candidate;
        blocked.insert(candidate.direction);
        heading = opposite(candidate.direction);
    }
}

class RouteBudget final {
public:
    explicit RouteBudget(std::uint8_t steps) : total(steps) {}
    void enter(std::int16_t tile, std::int32_t object) {
        if (object == 30 && extended.size() < maximum_extensions && extended.insert(tile).second) ++total;
    }
    std::size_t total;
private:
    std::set<std::int16_t> extended;
};
}

OriginalRouteTrace build_original_route(std::shared_ptr<const OriginalMapResources> map,
    const OriginalRouteRequest& request, const OriginalRouteRandom& random) {
    const Geometry geometry(map,request);
    if (!random) throw CodecError("original_route_random_missing");
    OriginalRouteTrace trace;
    RouteBudget budget(request.steps);
    auto current = request.start;
    auto heading = request.direction;
    while (trace.size() < budget.total) {
        const auto origin = geometry.origin(current,trace.size());
        auto first = trace.empty() ? request.rules.first_direction : std::nullopt;
        if (trace.empty() && !first && geometry.neighbor(origin,heading)) first = heading;
        const auto step = choose_step(geometry,origin,heading,first,random);
        trace.push_back(step);
        current = step.tile; heading = step.direction;
        const auto object = geometry.object(current);
        if (object == 11) break;
        budget.enter(current,object);
        if (budget.total > maximum_steps) throw CodecError("original_route_capacity_exceeded");
    }
    return trace;
}

OriginalRouteTrace reconstruct_original_route(std::shared_ptr<const OriginalMapResources> map,
    const OriginalRouteRequest& request, std::span<const std::uint8_t> directions) {
    const Geometry geometry(map,request);
    if (directions.empty() || directions.size() > maximum_steps) throw CodecError("original_route_count_invalid");
    OriginalRouteTrace trace;
    RouteBudget budget(request.steps);
    auto current = request.start;
    bool stopped = false;
    for (const auto direction : directions) {
        if (trace.size() >= budget.total || stopped) throw CodecError("original_route_count_invalid");
        const auto next = geometry.neighbor(geometry.origin(current,trace.size()),direction);
        if (!next) throw CodecError("original_route_step_unwalkable");
        current = *next;
        trace.push_back({current,direction});
        const auto object = geometry.object(current);
        stopped = object == 11;
        budget.enter(current,object);
    }
    if (!stopped && trace.size() != budget.total) throw CodecError("original_route_count_invalid");
    return trace;
}
}
