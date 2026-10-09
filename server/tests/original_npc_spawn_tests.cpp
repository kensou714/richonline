#include "original_npc_spawn.hpp"
#include <algorithm>
#include <iostream>
#include <set>

namespace {
using namespace richnet;
void check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}
template<class Action> void rejects(Action action, std::string_view code) {
    try { action(); }
    catch (const CodecError& error) {
        check(error.what() == code,std::string("expected ")+std::string(code)+", got "+error.what());
        return;
    }
    throw std::runtime_error("expected rejection: "+std::string(code));
}
std::shared_ptr<OriginalMapResources> map_fixture(std::int16_t cells = 20) {
    auto map = std::make_shared<OriginalMapResources>();
    for (std::int16_t i = 0; i < cells; ++i) map->roads.push_back({i,-1,0});
    return map;
}
const OriginalRouteRandom first = [](std::uint32_t count) { check(count > 0,"random called on empty choices"); return 0U; };
const OriginalRouteRandom last = [](std::uint32_t count) { check(count > 0,"random called on empty choices"); return count-1; };
void apply_spawns(std::map<std::int16_t,std::int32_t>& objects, const OriginalNpcSpawnResult& result) {
    for (const auto& spawn : result.spawned) check(objects.emplace(spawn.tile,spawn.kind).second,"spawn overwrote existing object");
}
void initial_population_and_exclusions() {
    auto map = map_fixture(); map->roads[0].property_id = 7;
    OriginalNpcSpawner spawner(map);
    std::map<std::int16_t,std::int32_t> objects{{1,10},{3,11}};
    const std::array<std::int16_t,2> occupied{2,4};
    const auto initial = spawner.initial(100,{objects,occupied},first);
    const std::vector<OriginalNpcSpawn> expected{{5,0},{6,1},{7,2},{8,3},{9,9}};
    check(initial.spawned == expected && !initial.space_exhausted && initial.missing_minimum == 0,
          "opening selects four different gods and one chest, excluding property/player/object tiles");
    check(objects == std::map<std::int16_t,std::int32_t>{{1,10},{3,11}},"spawn planning never changes input objects");
    apply_spawns(objects,initial);
    rejects([&] { spawner.initial(100,{objects,occupied},first); },"original_npc_already_initialized");
    OriginalNpcSpawner high(map_fixture(5));
    const std::map<std::int16_t,std::int32_t> empty;
    check(high.initial(0,{empty,{}},last).spawned == std::vector<OriginalNpcSpawn>{{4,7},{3,6},{2,4},{1,3},{0,9}},
          "upper random bound selects last free tile and distinct gods");
}
void third_turn_period_and_interval_coalescing() {
    OriginalNpcSpawner spawner(map_fixture());
    const std::map<std::int16_t,std::int32_t> empty;
    spawner.initial(40,{empty,{}},first);
    std::map<std::int16_t,std::int32_t> objects{{0,0},{1,9}};
    check(spawner.advance(41,{objects,{}},{}).spawned.empty(),"no periodic spawn on first turn");
    check(spawner.advance(42,{objects,{}},{}).spawned.empty(),"no periodic spawn on second turn");
    auto result = spawner.advance(43,{objects,{}},first);
    check(result.spawned == std::vector<OriginalNpcSpawn>{{2,0}},"first periodic spawn occurs on third turn");
    apply_spawns(objects,result);
    check(spawner.advance(43,{objects,{}},{}).spawned.empty(),"same context cannot emit twice");
    check(spawner.advance(44,{objects,{}},{}).spawned.empty(),"fourth turn does not shift cadence");
    result = spawner.advance(47,{objects,{}},first);
    check(result.spawned.size() == 1,"skipping exact sixth-turn call still services its interval");
    apply_spawns(objects,result);
    result = spawner.advance(56,{objects,{}},first);
    check(result.spawned.size() == 1,"missed intervals coalesce to one spawn rather than a burst");
    apply_spawns(objects,result);
    check(objects.size() == 5 && spawner.advance(58,{objects,{}},{}).spawned.empty(),"cap suppresses periodic random draw");
    objects.erase(0);
    check(spawner.advance(58,{objects,{}},{}).spawned.empty(),"already processed capped interval cannot be replayed after removal");
}
void context_wrap_and_random_failure_are_atomic() {
    const std::map<std::int16_t,std::int32_t> empty;
    std::map<std::int16_t,std::int32_t> objects{{0,0},{1,9}};
    OriginalNpcSpawner spawner(map_fixture());
    unsigned draws = 0;
    const OriginalRouteRandom faulty = [&](std::uint32_t count) { return ++draws == 2 ? count : 0U; };
    rejects([&] { spawner.initial(0xfffffffe,{empty,{}},faulty); },"original_npc_random_out_of_range");
    spawner.initial(0xfffffffe,{empty,{}},first);
    check(spawner.advance(0xffffffff,{objects,{}},{}).spawned.empty(),"prewrap first turn");
    check(spawner.advance(0,{objects,{}},{}).spawned.empty(),"wrapped second turn");
    draws = 0;
    rejects([&] { spawner.advance(1,{objects,{}},faulty); },"original_npc_random_out_of_range");
    check(spawner.advance(1,{objects,{}},first).spawned.size() == 1,"failed random selection does not consume wrapped third-turn interval");
    rejects([&] { spawner.advance(0,{objects,{}},first); },"original_npc_context_out_of_order");
    check(spawner.advance(1,{objects,{}},{}).spawned.empty(),"stale context rejection preserves last successfully processed context");
    check(objects == std::map<std::int16_t,std::int32_t>{{0,0},{1,9}},"failed or successful selection never partially mutates input");
}
void minimum_and_insufficient_space() {
    const std::map<std::int16_t,std::int32_t> empty;
    OriginalNpcSpawner spawner(map_fixture(5));
    spawner.initial(0,{empty,{}},first);
    auto result = spawner.refill({empty,{}},first);
    check(result.spawned == std::vector<OriginalNpcSpawn>{{0,0},{1,0}} && result.missing_minimum == 0 && !result.space_exhausted,
          "event refill immediately restores lower bound without requiring unique gods");
    const std::array<std::int16_t,4> occupied{1,2,3,4};
    result = spawner.refill({empty,occupied},first);
    check(result.spawned.size() == 1 && result.missing_minimum == 1 && result.space_exhausted,"partial space reports exact remaining minimum deficit");
    std::map<std::int16_t,std::int32_t> blocked{{0,10}};
    result = spawner.refill({blocked,occupied},{});
    check(result.spawned.empty() && result.missing_minimum == 2 && result.space_exhausted,"no space terminates without random draw or loop");
    for (const auto kind : {5,32}) {
        const std::map<std::int16_t,std::int32_t> counted{{0,kind},{1,9}};
        result = spawner.refill({counted,{}},{});
        check(result.spawned.empty() && result.missing_minimum == 0,"other existing NPC and treasure kinds count toward minimum");
    }
    const std::map<std::int16_t,std::int32_t> lottery{{0,33}};
    result = spawner.refill({lottery,{}},first);
    check(result.spawned == std::vector<OriginalNpcSpawn>{{1,0},{2,0}},"lottery card blocks its tile but is neither NPC nor chest population");
    const std::map<std::int16_t,std::int32_t> capped{{0,0},{1,1},{2,5},{3,32},{4,9}};
    check(spawner.refill({capped,{}},{}).spawned.empty(),"five existing NPCs need no replenishment");
    auto excess = capped; excess.emplace(9,9);
    rejects([&] { spawner.refill({excess,{}},first); },"original_npc_population_exceeds_limit");
}
void validation_and_actual_map() {
    const std::map<std::int16_t,std::int32_t> empty;
    rejects([] { OriginalNpcSpawner absent(nullptr); },"original_npc_map_required");
    auto invalid = map_fixture(); invalid->roads.push_back(invalid->roads[0]);
    rejects([&] { OriginalNpcSpawner duplicate(invalid); },"original_npc_road_invalid");
    OriginalNpcSpawner small(map_fixture(4));
    rejects([&] { small.initial(0,{empty,{}},first); },"original_npc_initial_space_insufficient");
    OriginalNpcSpawner pending(map_fixture());
    rejects([&] { pending.advance(0,{empty,{}},first); },"original_npc_not_initialized");
    rejects([&] { pending.refill({empty,{}},first); },"original_npc_not_initialized");
    const std::map<std::int16_t,std::int32_t> conflict{{1,9}};
    rejects([&] { pending.initial(0,{conflict,{}},first); },"original_npc_initial_population_conflict");
    rejects([&] { pending.initial(0,{empty,{}},{}); },"original_npc_random_required");
    constexpr std::string_view file = __FILE__;
    const auto root = std::filesystem::path(std::u8string(file.begin(),file.end())).parent_path().parent_path().parent_path();
    const auto map = std::make_shared<OriginalMapResources>(original_map_resources(load_original_emp(root/"Map"/"BS_1_1.emp"),10));
    OriginalNpcSpawner actual(map);
    const auto result = actual.initial(1,{empty,{}},last);
    std::set<std::int16_t> tiles;
    for (const auto& spawn : result.spawned) {
        const auto road = std::find_if(map->roads.begin(),map->roads.end(),[&](const auto& item) { return item.tile == spawn.tile; });
        check(road != map->roads.end() && road->property_id == -1 && tiles.insert(spawn.tile).second,
              "actual BOSS map opening occupies five unique nonproperty roads");
    }
}
}
int main() {
    try {
        initial_population_and_exclusions(); third_turn_period_and_interval_coalescing(); context_wrap_and_random_failure_are_atomic();
        minimum_and_insufficient_space(); validation_and_actual_map();
        std::cout << "PASS original NPC local policy opening, thirds, interval replay, wrap, limits, random atomicity and actual map\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
