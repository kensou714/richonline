#include "original_game_startup_test_support.hpp"
#include "original_movement.hpp"

#include <iostream>

namespace {
using namespace original_startup_test;

struct MovementCounts {
    std::atomic_int actions{0}, landings{0}, directions{0}, released{0};
};

OriginalGamePlan movement_plan(std::shared_ptr<const OriginalMapResources> map, MovementCounts& counts) {
    // Startup/envelope opaque bytes and landing completion are test fixtures, not recovered gameplay rules.
    const OriginalMovementWirePolicy wire{{0xa5,0xb6,0xc7,0xd8,0xe9,0xfa,0x8b,0x9c,0xad,0xbe,0xcf,0xd0,0xe1},
        {0xfa,0xce},{0xbe,0xef}};
    auto movement = std::make_shared<OriginalMovement>(std::move(map),
        OriginalMovementSetup{0x3456,0,179,1,1,wire},[](std::uint32_t) { return 0U; });
    movement->set_effects({{{},false,{},{}},{},true});
    return {startup(),[] { return std::vector<Bytes>{turn}; },
        [movement,&counts](View plain) {
            ++counts.actions;
            const auto request = parse_original_movement_request(plain);
            auto result = movement->handle(request);
            if (result.event) {
                require(result.event->kind == OriginalStopKind::landing,"unexpected_tcp_bomb_event");
                ++counts.landings;
                if (!movement->wait_for_direction()) {
                    movement->finish_landing();
                    movement->begin_turn(static_cast<std::uint16_t>(movement->state().context+1U));
                    result.messages.push_back(turn);
                }
            }
            if (std::holds_alternative<OriginalDirectionChoice>(request)) {
                ++counts.directions;
                movement->finish_landing();
                movement->begin_turn(static_cast<std::uint16_t>(movement->state().context+1U));
                result.messages.push_back(turn);
            }
            return result.messages;
        },[&counts] { ++counts.released; }};
}

void start(const Client& client) {
    client.send(ticket(direct_admission()));
    require(client.plain() == expected_init(),"movement_startup_init_missing");
    client.send(message(Bytes{0,0}));
    require(client.plain() == expected_snapshot(),"movement_startup_snapshot_missing");
    require(client.plain() == turn,"movement_startup_turn_missing");
}

void expect_roll(const Client& client, std::uint8_t context, std::int16_t from, std::uint8_t direction) {
    client.send(message(Bytes{16,0,context,0,0,0,0,0}));
    Bytes expected{0x11,0x40,0x56,0x34,static_cast<std::uint8_t>(from),0,1,1,1,0,0,
        static_cast<std::uint8_t>(0xa4U|direction),0xb6,0xc7,0xd8,0xe9,0xfa,0x8b,0x9c,0xad,0xbe,0xcf,0xd0,0xe1,0,0,0,0};
    require(client.plain() == expected,"movement_roll_fields_or_route_direction_wrong");
}

void arrive_at_fork(const Client& client) {
    client.send(message(Bytes{17,0,0,0,178,0}));
    require(client.plain() == Bytes{0x13,0x40,0x56,0x34,178,0,0xfa,0xce},"movement_landing_reply_wrong");
}

void original_map_fork_survives_rejected_connections() {
    constexpr std::string_view source_path = __FILE__;
    const auto root = std::filesystem::path(std::u8string(source_path.begin(),source_path.end()))
        .parent_path().parent_path().parent_path();
    const auto map = std::make_shared<OriginalMapResources>(original_map_resources(
        load_original_emp(root / "Map" / "BS_1_1.emp"),10));
    require(std::find(map->edges.begin(),map->edges.end(),OriginalRoadEdge{179,178,1}) != map->edges.end(),
        "actual_map_initial_edge_missing");
    require(std::find(map->edges.begin(),map->edges.end(),OriginalRoadEdge{178,162,2}) != map->edges.end(),
        "actual_map_chosen_fork_edge_missing");
    MovementCounts counts;
    Running running([&] { return direct_callbacks(movement_plan(map,counts)); });
    const auto port = running.service.bound_port();
    const Client survivor(port);
    start(survivor);
    {
        const Client stale(port);
        start(stale);
        stale.send(message(Bytes{16,0,1,0,0,0,0,0}));
        stale.closed();
        require(counts.actions.load() == 0,"stale_context_reached_movement_strategy");
    }
    {
        const Client replay(port);
        start(replay);
        expect_roll(replay,0,179,1);
        arrive_at_fork(replay);
        replay.send(message(Bytes{17,0,0,0,178,0}));
        replay.closed();
        require(counts.landings.load() == 1,"replayed_move_resolved_landing_twice");
    }
    expect_roll(survivor,0,179,1);
    arrive_at_fork(survivor);
    survivor.send(message(Bytes{52,0,0,0,2,0x93}));
    require(survivor.plain() == Bytes{0x35,0x40,0x56,0x34,2,0xbe,0xef},"movement_direction_reply_wrong");
    require(survivor.plain() == turn,"movement_next_turn_missing_after_direction");
    expect_roll(survivor,1,178,2);
    survivor.send(message(Bytes{17,0,1,0,162,0}));
    require(survivor.plain() == Bytes{0x13,0x40,0x56,0x34,162,0,0xfa,0xce},"movement_chosen_route_landing_wrong");
    require(survivor.plain() == turn,"movement_next_turn_missing_after_second_landing");
    survivor.send(message(Bytes{10,0}));
    survivor.closed();
    running.finish();
    require(counts.actions.load() == 8 && counts.landings.load() == 3 && counts.directions.load() == 1,
        "movement_strategy_action_counts_wrong");
    require(counts.released.load() == 3,"movement_session_cleanup_count_wrong");
}
}

int main() {
    try {
        const Network network;
        original_map_fork_survives_rejected_connections();
        std::cout << "PASS original movement encrypted TCP, real BS_1_1 fork, retained direction and isolated rejections.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
