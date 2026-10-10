#include "richonline_route.hpp"
#include "original_map.hpp"
#include <algorithm>
#include <bit>
#include <utility>

namespace richnet {
namespace {
void require_array(View bytes, std::size_t offset, std::size_t count, std::size_t stride) {
    if (offset > bytes.size() || count > (bytes.size()-offset)/stride)
        throw CodecError("richonline_route_map_truncated");
}
void require_ordinary(const RichonlineRoadCell& cell, bool banks_enabled) {
    if ((cell.static_type == 9 && !banks_enabled) || cell.static_type == 67)
        throw CodecError("richonline_route_static_effect_unsupported");
}
}
RichonlineRoadTopology::RichonlineRoadTopology(std::uint32_t width, std::uint32_t height,
    std::vector<RichonlineRoadCell> cells) : width_(width), height_(height), cells_(std::move(cells)) {}

const RichonlineRoadCell& RichonlineRoadTopology::cell(std::int16_t position) const {
    if (position < 0 || static_cast<std::size_t>(position) >= cells_.size())
        throw CodecError("richonline_route_position_invalid");
    return cells_[static_cast<std::size_t>(position)];
}

std::optional<std::int16_t> RichonlineRoadTopology::portal_destination(std::int16_t position) const {
    const auto& source=cell(position);
    if(source.static_type!=61) return {};
    if(!portals_) throw CodecError("richonline_route_portal_pair_missing");
    if(position==(*portals_)[0]) return (*portals_)[1];
    if(position==(*portals_)[1]) return (*portals_)[0];
    throw CodecError("richonline_route_portal_pair_invalid");
}

RichonlineRoadTopology richonline_road_topology(const OriginalEmp& emp) {
    const auto area = static_cast<std::uint64_t>(emp.width)*emp.height;
    if (emp.width == 0 || emp.height == 0 || area > 32768)
        throw CodecError("richonline_route_dimensions_invalid");
    const auto count = static_cast<std::size_t>(area);
    const View payload(emp.payload);
    require_array(payload,0,2,4);
    require_array(payload,emp.terrain_offset,count,64);
    require_array(payload,emp.tile_types_offset,count,4);
    std::vector<RichonlineRoadCell> cells;
    cells.reserve(count);
    // New loader7DF010: low terrain byte -> map+48; static byte -> map+52.
    for (std::size_t i = 0; i < count; ++i) {
        const auto terrain = std::bit_cast<std::int8_t>(payload[emp.terrain_offset+64*i]);
        const auto type = std::bit_cast<std::int8_t>(payload[emp.tile_types_offset+4*i]);
        const auto property_x = read_le(payload.subspan(emp.terrain_offset+64*i+56,4));
        const auto property_y = read_le(payload.subspan(emp.terrain_offset+64*i+60,4));
        std::int16_t property_ref = -1;
        if (property_x != 0xffffffffU) {
            if (property_x >= emp.width || property_y >= emp.height)
                throw CodecError("richonline_route_property_position_invalid");
            property_ref = static_cast<std::int16_t>(property_y*emp.width+property_x);
        }
        cells.push_back({static_cast<std::int16_t>(i),terrain,type,property_ref,terrain != -1,{}});
    }
    const auto x = read_le(payload.subspan(0,4));
    const auto y = read_le(payload.subspan(4,4));
    if (x != 0xffffffffU && y != 0xffffffffU) {
        if (x >= emp.width || y >= emp.height)
            throw CodecError("richonline_route_special_position_invalid");
        cells[static_cast<std::size_t>(y)*emp.width+x].static_type = 7;
    }
    for (std::size_t i = 0; i < count; ++i) {
        if (!cells[i].walkable) continue;
        const auto column = i%emp.width;
        const auto row = i/emp.width;
        const std::array<std::optional<std::size_t>,4> adjacent{
            row+1 < emp.height ? std::optional{i+emp.width} : std::nullopt,
            column > 0 ? std::optional{i-1} : std::nullopt,
            row > 0 ? std::optional{i-emp.width} : std::nullopt,
            column+1 < emp.width ? std::optional{i+1} : std::nullopt};
        for (std::size_t direction = 0; direction < adjacent.size(); ++direction)
            if (adjacent[direction] && cells[*adjacent[direction]].walkable)
                cells[i].neighbors[direction] = static_cast<std::int16_t>(*adjacent[direction]);
    }
    RichonlineRoadTopology result(emp.width,emp.height,std::move(cells));
    // NEW7DF010 loads map+70/+72 from these two coordinate pairs.
    // Maps without a jail may use unavailable coordinates; they remain playable.
    if(emp.tail_offset<=payload.size() && payload.size()-emp.tail_offset>=48) {
        std::array<std::int16_t,2> jail{};
        bool available=true;
        for(std::size_t i=0;i<jail.size();++i) {
            const auto jx=read_le(payload.subspan(emp.tail_offset+32+8*i,4));
            const auto jy=read_le(payload.subspan(emp.tail_offset+36+8*i,4));
            if(jx>=emp.width || jy>=emp.height) { available=false;break; }
            jail[i]=static_cast<std::int16_t>(jy*emp.width+jx);
            if(!result.cell(jail[i]).walkable) { available=false;break; }
        }
        if(available && jail[0]!=jail[1]) result.jail_=jail;
    }
    const auto portals=std::count_if(result.cells_.begin(),result.cells_.end(),
        [](const auto& entry){return entry.walkable && entry.static_type==61;});
    if(portals!=0) {
        if(portals!=2) throw CodecError("richonline_route_portal_pair_invalid");
        require_array(payload,emp.tail_offset,24,4);
        std::array<std::int16_t,2> pair{};
        for(std::size_t i=0;i<pair.size();++i) {
            const auto px=read_le(payload.subspan(emp.tail_offset+80+8*i,4));
            const auto py=read_le(payload.subspan(emp.tail_offset+84+8*i,4));
            if(px>=emp.width || py>=emp.height) throw CodecError("richonline_route_portal_position_invalid");
            pair[i]=static_cast<std::int16_t>(py*emp.width+px);
            const auto& endpoint=result.cell(pair[i]);
            if(!endpoint.walkable || endpoint.static_type!=61) throw CodecError("richonline_route_portal_pair_invalid");
        }
        if(pair[0]==pair[1]) throw CodecError("richonline_route_portal_pair_invalid");
        result.portals_=pair;
    }
    return result;
}

RichonlineRoadTopology load_richonline_road_topology(const std::filesystem::path& path) {
    return richonline_road_topology(load_original_emp(path));
}

RichonlineRoute build_richonline_route(const RichonlineRoadTopology& topology,
    const RichonlineRouteRequest& request, const RichonlineRouteChooser& chooser,
    const RichonlineRouteBudget& extend_budget) {
    if (request.budget < 1 || request.budget > 18)
        throw CodecError("richonline_route_budget_invalid");
    if (request.heading > 3 || (request.first_direction && *request.first_direction > 3))
        throw CodecError("richonline_route_direction_invalid");
    const auto& start = topology.cell(request.start);
    if (!start.walkable) throw CodecError("richonline_route_start_blocked");
    require_ordinary(start,request.banks_enabled);
    RichonlineRoute route;
    route.directions.reserve(static_cast<std::size_t>(request.budget));
    route.landings.reserve(static_cast<std::size_t>(request.budget));
    auto position = request.start;
    auto heading = request.heading;
    auto budget = request.budget;
    // 7E1C60 takes the initial heading, then7E1A40/7E1B10 exclude reverse unless trapped.
    for (std::int32_t step = 0; step < budget; ++step) {
        // NEW 7F71D0 applies paired transport before the next direction, never after the last step.
        if(step!=0 && request.portals_enabled)
            if(const auto exit=topology.portal_destination(position)) position=*exit;
        const auto& cell = topology.cell(position);
        std::uint8_t direction = heading;
        if (step == 0 && request.first_direction) {
            direction = *request.first_direction;
            if (!cell.neighbors[direction]) throw CodecError("richonline_route_first_step_invalid");
        } else if (step != 0 || !cell.neighbors[heading]) {
            const auto reverse = static_cast<std::uint8_t>((heading+2U)%4U);
            std::array<std::uint8_t,4> candidates{};
            std::size_t size = 0;
            for (std::uint8_t candidate = 0; candidate < 4; ++candidate)
                if (candidate != reverse && cell.neighbors[candidate]) candidates[size++] = candidate;
            if (size == 0) {
                if (!cell.neighbors[reverse]) throw CodecError("richonline_route_dead_end");
                direction = reverse;
            } else if (size == 1) {
                direction = candidates[0];
            } else {
                if (!chooser) throw CodecError("richonline_route_chooser_missing");
                const auto choice = chooser(size);
                if (choice >= size) throw CodecError("richonline_route_choice_invalid");
                direction = candidates[choice];
            }
        }
        position = *cell.neighbors[direction];
        require_ordinary(topology.cell(position),request.banks_enabled);
        route.directions.push_back(direction);
        route.landings.push_back(position);
        heading = direction;
        if (extend_budget) {
            const auto extended=extend_budget(position,step+1,budget);
            if(extended<budget || extended>36) throw CodecError("richonline_route_extended_budget_invalid");
            budget=extended;
        }
    }
    return route;
}
}
