#include "richonline_route.hpp"
#include "original_map.hpp"
#include <algorithm>
#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
void check(bool value, std::string_view reason) {
    if (!value) throw std::runtime_error(std::string(reason));
}
template<class F> void rejects(F action, std::string_view code) {
    try { action(); } catch (const CodecError& error) { check(error.what() == code, error.what()); return; }
    throw std::runtime_error("expected_rejection");
}
void put(Bytes& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) bytes.at(offset+i) = static_cast<std::uint8_t>(value >> (8*i));
}
OriginalEmp geometry(std::uint32_t width, std::uint32_t height,
    std::initializer_list<std::size_t> roads) {
    const auto count = static_cast<std::size_t>(width)*height;
    OriginalEmp emp{3,width,height,{}, {}, Bytes(8+68*count,0xff),8,8+64*count,0,0};
    for (const auto cell : roads) emp.payload.at(emp.terrain_offset+64*cell) = 8;
    return emp;
}
const RichonlineRouteChooser first = [](std::size_t) { return std::size_t{0}; };
void actual_bs_map(const std::filesystem::path& root) {
    // Given the exact new-client map, including the special XY override.
    const auto emp = load_original_emp(root/"Map"/"BS_1_1.emp");
    const std::array<std::uint8_t,16> signature{0x77,0x2a,0x81,0xa7,0x87,0x67,0x85,0x52,
        0x15,0x57,0x8e,0xcf,0xf3,0x9c,0x3a,0xbe};
    check(emp.signature == signature, "test_requires_new_client_resource");
    const auto topology = load_richonline_road_topology(root/"Map"/"BS_1_1.emp");
    check(topology.width() == 16 && topology.height() == 18, "new_dimensions");
    check(std::count_if(topology.cells().begin(),topology.cells().end(),
        [](const auto& cell) { return cell.walkable; }) == 46, "new_road_count");
    check(topology.cell(230).static_type == 7 && topology.cell(114).static_type == 68,
        "new_static_tile_projection");
    check(topology.cell(119).property_ref == 104 && topology.cell(120).property_ref == 104 &&
        topology.cell(146).property_ref == 164 && topology.cell(231).property_ref == 216 &&
        topology.cell(115).property_ref == -1, "new_property_coordinate_projection");
    // When following the known southwest corner from the resource-derived spawn.
    const auto route = build_richonline_route(topology,{115,1,4,{}},first);
    // Then directions turn using this resource's geometry, not fixed increments.
    check(route.directions == std::vector<std::uint8_t>{1,0,0,0} &&
        route.landings == std::vector<std::int16_t>{114,130,146,162}, "actual_corner_route");
    const auto full = build_richonline_route(topology,{115,1,18,{}},first);
    check(full.landings.size() == 18 && full.directions.size() == 18, "budget_18");
    auto changed = emp;
    changed.payload[changed.terrain_offset+64*114] = 0xff;
    const auto rerouted = build_richonline_route(richonline_road_topology(changed),{115,1,2,{}},first);
    check(rerouted.landings == std::vector<std::int16_t>{116,117}, "real_resource_mutation_ignored");
}
void actual_zhao_portal_route(const std::filesystem::path& root) {
    const auto emp=load_original_emp(root/"Map"/"V_BS_1_1.emp");
    const auto topology=richonline_road_topology(emp);
    check(topology.portal_destination(105)==229 && topology.portal_destination(229)==105 &&
        !topology.portal_destination(106),"zhao_resource_portal_pair");
    const std::vector<std::int16_t> expected{105,228,227,226,210,194};
    const std::vector<std::uint8_t> directions{1,1,1,1,2,2};
    for(std::int32_t die=1;die<=6;++die) {
        const auto route=build_richonline_route(topology,{106,1,die,{}},first);
        check(route.landings==std::vector<std::int16_t>(expected.begin(),expected.begin()+die),"zhao_portal_steps");
        check(route.directions==std::vector<std::uint8_t>(directions.begin(),directions.begin()+die),"zhao_portal_directions");
    }
    const auto reverse=build_richonline_route(topology,{228,3,3,{}},first);
    check(reverse.landings==std::vector<std::int16_t>{229,106,107},"reverse_portal_route");
    const auto first_step=build_richonline_route(topology,{105,3,1,{}},first);
    check(first_step.landings==std::vector<std::int16_t>{106},"starting_on_portal_does_not_preteleport");
    const auto suppressed=build_richonline_route(topology,{106,1,2,{},false},first);
    check(suppressed.landings==std::vector<std::int16_t>{105,106},"status_can_suppress_portal");
    auto malformed=emp;
    malformed.payload.resize(emp.tail_offset+95);
    rejects([&]{richonline_road_topology(malformed);},"richonline_route_map_truncated");
    malformed=emp; put(malformed.payload,emp.tail_offset+80,emp.width);
    rejects([&]{richonline_road_topology(malformed);},"richonline_route_portal_position_invalid");
    malformed=emp; put(malformed.payload,emp.tail_offset+88,9); put(malformed.payload,emp.tail_offset+92,6);
    rejects([&]{richonline_road_topology(malformed);},"richonline_route_portal_pair_invalid");
    malformed=emp; put(malformed.payload,emp.tail_offset+88,10);
    rejects([&]{richonline_road_topology(malformed);},"richonline_route_portal_pair_invalid");
    malformed=emp; put(malformed.payload,emp.tile_types_offset+4*229,8);
    rejects([&]{richonline_road_topology(malformed);},"richonline_route_portal_pair_invalid");
    malformed=emp; put(malformed.payload,emp.tile_types_offset+4*106,61);
    rejects([&]{richonline_road_topology(malformed);},"richonline_route_portal_pair_invalid");
}
void boundaries_and_changed_geometry() {
    // Given adjacent linear positions on separate rows and an isolated cell.
    const auto broken = richonline_road_topology(geometry(3,2,{2,3}));
    check(!broken.cell(2).neighbors[3] && !broken.cell(3).neighbors[1], "row_wrap_edge");
    rejects([&] { build_richonline_route(broken,{2,3,1,{}},first); }, "richonline_route_dead_end");
    // When geometry changes, the route bends and may reverse only at a dead end.
    const auto corner = richonline_road_topology(geometry(3,3,{1,4,5}));
    const auto route = build_richonline_route(corner,{1,0,4,{}},first);
    check(route.directions == std::vector<std::uint8_t>{0,3,1,2} &&
        route.landings == std::vector<std::int16_t>{4,5,4,1}, "geometry_corner_and_dead_end");
    const auto single_column = richonline_road_topology(geometry(1,3,{0,1,2}));
    check(!single_column.cell(1).neighbors[1] && !single_column.cell(1).neighbors[3],
        "single_column_horizontal_edges");
}
void heading_choice_and_random_forks() {
    // Given a four-way crossing, after the first heading step the reverse is excluded.
    const auto cross = richonline_road_topology(geometry(3,3,{1,3,4,5,7}));
    std::size_t calls = 0;
    const auto route = build_richonline_route(cross,{1,0,2,{}},[&](std::size_t count) {
        ++calls; check(count == 3, "fork_candidate_count"); return std::size_t{2};
    });
    check(calls == 1 && route.directions == std::vector<std::uint8_t>{0,3} &&
        route.landings.back() == 5, "random_fork_or_first_heading");
    const auto explicit_route = build_richonline_route(cross,{4,0,1,1},first);
    check(explicit_route.landings == std::vector<std::int16_t>{3}, "explicit_first_choice");
    const auto blocked_heading = build_richonline_route(cross,{1,3,1,{}},first);
    check(blocked_heading.landings == std::vector<std::int16_t>{4}, "blocked_heading_fallback");
    rejects([&] { build_richonline_route(cross,{1,0,2,{}},[](std::size_t n) { return n; }); },
        "richonline_route_choice_invalid");
    rejects([&] { build_richonline_route(cross,{1,0,2,{}},{}); }, "richonline_route_chooser_missing");
    const auto no_fork = build_richonline_route(cross,{1,0,1,{}},{});
    check(no_fork.landings == std::vector<std::int16_t>{4}, "unnecessary_random_choice");
}
void invalid_requests_and_special_tiles() {
    auto emp = geometry(3,1,{0,1,2});
    const auto topology = richonline_road_topology(emp);
    for (const auto budget : {0,-1,19})
        rejects([&] { build_richonline_route(topology,{0,3,budget,{}},first); }, "richonline_route_budget_invalid");
    rejects([&] { build_richonline_route(topology,{0,4,1,{}},first); }, "richonline_route_direction_invalid");
    rejects([&] { build_richonline_route(topology,{0,3,1,4},first); }, "richonline_route_direction_invalid");
    rejects([&] { build_richonline_route(topology,{0,3,1,2},first); }, "richonline_route_first_step_invalid");
    rejects([&] { build_richonline_route(topology,{-1,3,1,{}},first); }, "richonline_route_position_invalid");
    rejects([&] { build_richonline_route(topology,{3,3,1,{}},first); }, "richonline_route_position_invalid");
    for (const auto type : {9U,67U}) {
        put(emp.payload,emp.tile_types_offset+4,type);
        const auto special = richonline_road_topology(emp);
        rejects([&] { build_richonline_route(special,{0,3,2,{}},first); }, "richonline_route_static_effect_unsupported");
        rejects([&] { build_richonline_route(special,{1,3,1,{}},first); }, "richonline_route_static_effect_unsupported");
    }
    const auto blocked = richonline_road_topology(geometry(2,1,{1}));
    rejects([&] { build_richonline_route(blocked,{0,3,1,{}},first); }, "richonline_route_start_blocked");
}
void malformed_container_metadata() {
    auto emp = geometry(3,2,{0,1});
    emp.payload.pop_back();
    rejects([&] { richonline_road_topology(emp); }, "richonline_route_map_truncated");
    emp = geometry(3,2,{0,1}); emp.width = 0;
    rejects([&] { richonline_road_topology(emp); }, "richonline_route_dimensions_invalid");
    emp = geometry(3,2,{0,1}); emp.width = 32769;
    rejects([&] { richonline_road_topology(emp); }, "richonline_route_dimensions_invalid");
    emp = geometry(3,2,{0,1}); put(emp.payload,0,3); put(emp.payload,4,0);
    rejects([&] { richonline_road_topology(emp); }, "richonline_route_special_position_invalid");
}
void property_references_are_independent_of_static_types() {
    auto emp = geometry(3,2,{1});
    put(emp.payload,emp.terrain_offset+64+56,2); put(emp.payload,emp.terrain_offset+64+60,1);
    put(emp.payload,emp.tile_types_offset+4,0);
    const auto topology = richonline_road_topology(emp);
    check(topology.cell(1).property_ref == 5 && topology.cell(1).static_type == 0 &&
        !topology.cell(5).walkable, "property_ref_is_not_static_type_or_road_neighbor");
    for (const auto xy : {std::array<std::uint32_t,2>{3,0},{0,2},{0xffffffffU-1,0},
                         {0,0xffffffffU},{65536,0},{0,65536}}) {
        put(emp.payload,emp.terrain_offset+64+56,xy[0]);
        put(emp.payload,emp.terrain_offset+64+60,xy[1]);
        rejects([&] { richonline_road_topology(emp); }, "richonline_route_property_position_invalid");
    }
    put(emp.payload,emp.terrain_offset+64+56,0xffffffffU);
    put(emp.payload,emp.terrain_offset+64+60,42);
    check(richonline_road_topology(emp).cell(1).property_ref == -1, "property_x_sentinel_ignores_y");
}
void projected_route_budget_extends_without_rerolling() {
    const auto topology=richonline_road_topology(geometry(5,1,{0,1,2,3,4}));
    std::size_t calls=0;
    const auto route=build_richonline_route(topology,{0,3,1,{}},{},
        [&](std::int16_t position,std::int32_t step,std::int32_t budget) {
            ++calls;check(step==position,"extension_callback_not_in_route_order");
            return position<=2 ? budget+1 : budget;
        });
    check(route.landings==std::vector<std::int16_t>{1,2,3} && calls==3,"projected_budget_not_extended");
    rejects([&]{build_richonline_route(topology,{0,3,1,{}},{},
        [](std::int16_t,std::int32_t,std::int32_t){return 0;});},"richonline_route_extended_budget_invalid");
    rejects([&]{build_richonline_route(topology,{0,3,1,{}},{},
        [](std::int16_t,std::int32_t,std::int32_t){return 37;});},"richonline_route_extended_budget_invalid");
    const auto maximal=build_richonline_route(topology,{0,3,1,{}},{},
        [](std::int16_t,std::int32_t,std::int32_t){return 36;});
    check(maximal.landings.size()==36,"36_direction_slots_not_supported");
}
}
int main(int argc, char** argv) {
    try {
        if (argc != 2) throw std::runtime_error("usage: richonline_route_tests <Richonline-resource-root>");
        actual_bs_map(std::filesystem::path(argv[1])); boundaries_and_changed_geometry();
        actual_zhao_portal_route(std::filesystem::path(argv[1]));
        heading_choice_and_random_forks(); invalid_requests_and_special_tiles(); malformed_container_metadata();
        property_references_are_independent_of_static_types();
        projected_route_budget_extends_without_rerolling();
        std::cout << "PASS new-client static topology and ordinary routes\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
