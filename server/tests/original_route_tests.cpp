#include "original_route.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value, std::string_view message) {
    if (!value) throw std::runtime_error(std::string(message));
}
void rejects(const std::function<void()>& action, std::string_view code) {
    try { action(); } catch (const CodecError& error) {
        check(error.what() == code,std::string("unexpected rejection: ")+error.what()); return;
    }
    throw std::runtime_error("expected rejection missing");
}
std::shared_ptr<OriginalMapResources> grid(std::uint32_t width, std::uint32_t height,
    std::initializer_list<std::int16_t> roads) {
    auto map = std::make_shared<OriginalMapResources>();
    map->emp.width = width; map->emp.height = height;
    for (const auto tile : roads) map->roads.push_back({tile,-1,0});
    return map;
}
OriginalRouteRequest request(std::int16_t start, std::uint8_t direction, std::uint8_t steps) {
    return {start,direction,steps,{{},false,std::nullopt,std::nullopt}};
}
const OriginalRouteRandom first = [](std::uint32_t) { return 0U; };
std::vector<std::uint8_t> directions(const OriginalRouteTrace& trace) {
    std::vector<std::uint8_t> result;
    for (const auto& step : trace) result.push_back(step.direction);
    return result;
}
void test_branch_and_dead_end() {
    const auto cross = grid(3,3,{1,3,4,5,7});
    auto input = request(1,0,2);
    std::uint32_t random_bound = 0;
    const auto chosen = build_original_route(cross,input,[&](std::uint32_t upper) { random_bound = upper; return 2U; });
    check(random_bound == 3 && chosen == OriginalRouteTrace{{4,0},{5,3}},"subsequent fork chooses among three nonreverse directions");
    input = request(4,0,1);
    check(build_original_route(cross,input,first) == OriginalRouteTrace{{7,0}},"first step preserves available current heading");
    input.rules.first_direction = 2;
    check(build_original_route(cross,input,first) == OriginalRouteTrace{{1,2}},"explicit initial fork direction wins");
    const auto line = grid(3,1,{0,1,2});
    check(build_original_route(line,request(2,3,2),first) == OriginalRouteTrace{{1,1},{0,1}},"dead end reverses without stalling");
    check(build_original_route(grid(2,2,{0,1,2}),request(0,1,1),first) == OriginalRouteTrace{{2,0}},"left boundary cannot wrap into prior row");
}
void test_road_objects() {
    const auto line = grid(5,1,{0,1,2,3,4});
    auto input = request(1,3,2); input.rules.first_direction = 3; input.rules.objects[2] = 29;
    check(build_original_route(line,input,first) == OriginalRouteTrace{{0,1},{1,3}},"29 reverses before entering without consuming a step");
    input = request(0,3,4); input.rules.objects[2] = 11;
    const OriginalRouteTrace stop{{1,3},{2,3}};
    check(build_original_route(line,input,first) == stop,"11 stops on entered roadblock");
    check(reconstruct_original_route(line,input,std::array<std::uint8_t,2>{3,3}) == stop,"11 permits shorter route count");
    rejects([&] { reconstruct_original_route(line,input,std::array<std::uint8_t,3>{3,3,3}); },"original_route_count_invalid");
    input.rules.objects = {{1,12},{2,27}};
    check(build_original_route(line,input,first) == OriginalRouteTrace{{1,3},{2,3},{3,3},{4,3}},"mines12/27 are not movement roadblocks");
    input = request(1,3,1); input.rules.objects = {{0,29},{2,29}};
    rejects([&] { build_original_route(line,input,first); },"original_route_trapped");
    input = request(0,3,1); input.rules.objects[1] = 29;
    check(reconstruct_original_route(line,input,std::array<std::uint8_t,1>{3}) == OriginalRouteTrace{{1,3}},
        "client reconstruction does not recheck server avoidance of29");
}
void test_conveyor_extensions() {
    const auto short_line = grid(2,1,{0,1});
    auto input = request(0,3,2); input.rules.objects[1] = 30;
    const OriginalRouteTrace expected{{1,3},{0,1},{1,3}};
    check(build_original_route(short_line,input,first) == expected,"same30 tile extends once even when revisited");
    check(reconstruct_original_route(short_line,input,std::array<std::uint8_t,3>{3,1,3}) == expected,"reconstructed30 budget must match");
    rejects([&] { reconstruct_original_route(short_line,input,std::array<std::uint8_t,2>{3,1}); },"original_route_count_invalid");
    auto long_line = grid(38,1,{}); input = request(0,3,18);
    for (std::int16_t tile = 0; tile < 38; ++tile) {
        long_line->roads.push_back({tile,-1,0});
        if (tile != 0) input.rules.objects[tile] = 30;
    }
    const auto trace = build_original_route(long_line,input,first);
    check(trace.size() == 36 && trace.back() == OriginalRouteStep{36,3},"unique30 extensions cap at18, total36");
    check(reconstruct_original_route(long_line,input,directions(trace)) == trace,"capacity36 reconstructs");
}
void test_portals() {
    const auto map = grid(7,1,{0,1,2,5,6});
    map->roads[1].type = 61; map->roads[3].type = 61;
    auto input = request(0,3,2); input.rules.teleports = true; input.rules.portals = {{1,5}};
    const OriginalRouteTrace expected{{1,3},{6,3}};
    check(build_original_route(map,input,first) == expected,"teleport occurs before second adjacency, not after first reported tile");
    check(reconstruct_original_route(map,input,std::array<std::uint8_t,2>{3,3}) == expected,"client route reconstructs teleport before later steps");
    input = request(1,3,1); input.rules.teleports = true; input.rules.portals = {{1,5}};
    check(build_original_route(map,input,first) == OriginalRouteTrace{{2,3}},"starting on61 does not teleport first step");
    input = request(0,3,2);
    check(build_original_route(map,input,first) == OriginalRouteTrace{{1,3},{2,3}},"sleepwalk/god7 caller can disable portals");
    input.rules.teleports = true;
    rejects([&] { build_original_route(map,input,first); },"original_route_portals_missing");
    input.rules.portals = {{1,2}};
    rejects([&] { build_original_route(map,input,first); },"original_route_portals_invalid");
    map->roads[1].type = 28; map->roads[3].type = 28; input.rules.portals.reset();
    check(build_original_route(map,input,first) == OriginalRouteTrace{{1,3},{2,3}},"type28 is not automatic route teleport");
}
void test_invalid_boundaries() {
    const auto map = grid(3,1,{0,1,2});
    rejects([&] { build_original_route({},request(0,3,1),first); },"original_route_map_missing");
    rejects([&] { build_original_route(map,request(0,3,0),first); },"original_route_steps_invalid");
    rejects([&] { build_original_route(map,request(0,3,19),first); },"original_route_steps_invalid");
    rejects([&] { build_original_route(map,request(-1,3,1),first); },"original_route_start_invalid");
    rejects([&] { build_original_route(map,request(0,4,1),first); },"original_route_direction_invalid");
    rejects([&] { build_original_route(map,request(0,3,1),{}); },"original_route_random_missing");
    auto input = request(0,3,1); input.rules.first_direction = 0;
    rejects([&] { build_original_route(map,input,first); },"original_route_first_direction_unavailable");
    input = request(0,3,1); input.rules.objects[8] = 11;
    rejects([&] { build_original_route(map,input,first); },"original_route_object_tile_invalid");
    const auto cross = grid(3,3,{1,3,4,5,7});
    rejects([&] { build_original_route(cross,request(1,0,2),[](std::uint32_t upper) { return upper; }); },"original_route_random_out_of_range");
    rejects([&] { build_original_route(grid(1,1,{0}),request(0,0,1),first); },"original_route_trapped");
    rejects([&] { reconstruct_original_route(map,request(0,3,2),std::array<std::uint8_t,1>{3}); },"original_route_count_invalid");
    rejects([&] { reconstruct_original_route(map,request(0,3,1),std::array<std::uint8_t,1>{4}); },"original_route_direction_invalid");
    rejects([&] { reconstruct_original_route(map,request(0,3,1),std::array<std::uint8_t,1>{0}); },"original_route_step_unwalkable");
    rejects([&] { reconstruct_original_route(map,request(0,3,1),std::array<std::uint8_t,2>{3,3}); },"original_route_count_invalid");
    rejects([&] { reconstruct_original_route(map,request(0,3,1),std::array<std::uint8_t,37>{}); },"original_route_count_invalid");
    map->roads.push_back({0,-1,0});
    rejects([&] { build_original_route(map,request(0,3,1),first); },"original_route_road_invalid");
}
void test_actual_boss_maps() {
    constexpr std::string_view source_path = __FILE__;
    const auto root = std::filesystem::path(std::u8string(source_path.begin(),source_path.end())).parent_path().parent_path().parent_path();
    for (int stage = 1; stage <= 4; ++stage) {
        const auto map = std::make_shared<OriginalMapResources>(original_map_resources(
            load_original_emp(root / "Map" / ("BS_1_"+std::to_string(stage)+".emp")),10));
        const auto edge = map->edges.at(0);
        auto input = request(edge.from,edge.direction,18); input.rules.first_direction = edge.direction;
        const auto trace = build_original_route(map,input,first);
        check(trace.size() == 18,"actual BOSS map supplies complete18-step path");
        check(reconstruct_original_route(map,input,directions(trace)) == trace,"actual BOSS map route matches client geometry");
        auto previous = input.start;
        for (const auto& step : trace) {
            const auto dx = step.tile%static_cast<std::int32_t>(map->emp.width)-previous%static_cast<std::int32_t>(map->emp.width);
            const auto dy = step.tile/static_cast<std::int32_t>(map->emp.width)-previous/static_cast<std::int32_t>(map->emp.width);
            check((step.direction == 0 && dx == 0 && dy == 1) || (step.direction == 1 && dx == -1 && dy == 0) ||
                (step.direction == 2 && dx == 0 && dy == -1) || (step.direction == 3 && dx == 1 && dy == 0),
                "independent coordinate difference verifies every actual map direction");
            previous = step.tile;
        }
    }
}
}
int main() {
    try {
        test_branch_and_dead_end(); test_road_objects(); test_conveyor_extensions(); test_portals();
        test_invalid_boundaries(); test_actual_boss_maps();
        std::cout << "PASS original route forks, dead ends, objects11/29/30, mines, portals, budgets and four BOSS maps.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
