#include "original_game_startup_test_support.hpp"
#include "original_movement.hpp"
#include "original_shop.hpp"

#include <iostream>

namespace {
using namespace original_startup_test;

struct ShopEvidence {
    std::atomic_int seconds{0}, actions{0}, closes{0}, turns{0}, releases{0};
    std::atomic<std::uint32_t> tickets{500};
    OriginalShopClock::time_point now() const { return OriginalShopClock::time_point{}+std::chrono::seconds(seconds.load()); }
};
struct ShopStrategy {
    OriginalMovement movement;
    std::optional<OriginalShop> shop;
    std::optional<std::uint16_t> closed_context;
    ShopEvidence& evidence;
    explicit ShopStrategy(std::shared_ptr<const OriginalMapResources> map, ShopEvidence& observations)
        : movement(std::move(map),{0x3456,0,179,1,1,
            {{0xa5,0xb6,0xc7,0xd8,0xe9,0xfa,0x8b,0x9c,0xad,0xbe,0xcf,0xd0,0xe1},{0xfa,0xce},{0xbe,0xef}}},
            [](std::uint32_t) { return 0U; }),evidence(observations) {
        movement.set_effects({{{},false,{},{}},{},true});
    }
    std::vector<Bytes> finish_shop(OriginalShopResult result) {
        require(!result.rejection,"tcp_shop_unexpected_rejection");
        evidence.tickets.store(shop->wallet().tickets);
        if (result.closed && !closed_context) {
            closed_context = shop->context();
            ++evidence.closes;
            require(movement.wait_for_direction(),"tcp_shop_fork_not_waiting_after_close");
        }
        return result.messages;
    }
    std::vector<Bytes> action(View plain) {
        ++evidence.actions;
        const auto opcode = read_le(plain.first(2));
        if (opcode == 48 || opcode == 49 || opcode == 50 || opcode == 53) {
            require(shop.has_value(),"tcp_shop_action_before_landing");
            return finish_shop(shop->handle(parse_original_shop_request(plain),evidence.now()));
        }
        auto result = movement.handle(parse_original_movement_request(plain));
        if (result.event && result.event->cell.tile == 178) {
            // Catalog, refresh cost, startup fields and non-shop landing completion are explicit test policy.
            shop.emplace(OriginalShopSetup{0x3456,movement.state().context,0,evidence.now(),5},
                OriginalShopCatalog{{7,8},{7,8},{{7,30},{8,40}},{{7,1},{8,1}}},std::make_shared<OriginalCardCombinations>(),
                OriginalShopWallet{make_original_inventory(),500,100},[](std::uint32_t) { return 0U; });
            result.messages.push_back(shop->open_message());
        } else if (result.event || opcode == 52) {
            movement.finish_landing();
            movement.begin_turn(static_cast<std::uint16_t>(movement.state().context+1U));
            ++evidence.turns;
            result.messages.push_back(turn);
        }
        return result.messages;
    }
    std::vector<Bytes> poll() {
        if (!shop || shop->closed()) return {};
        return finish_shop(shop->poll(evidence.now()));
    }
};

OriginalGamePlan plan(std::shared_ptr<const OriginalMapResources> map, ShopEvidence& evidence) {
    auto strategy = std::make_shared<ShopStrategy>(std::move(map),evidence);
    return {startup(),[] { return std::vector<Bytes>{turn}; },
        [strategy](View plain) { return strategy->action(plain); },[&evidence] { ++evidence.releases; },
        [strategy] { return strategy->poll(); },[strategy] { return strategy->closed_context; }};
}
Bytes expected_stock() {
    Bytes bytes{0x30,0x40,0x56,0x34,7,0,1,0,0,0xff,8,0,1,0,0,0xff};
    for (int index = 2; index < 12; ++index) bytes.insert(bytes.end(),{0xff,0xff,0,0,0,0xff});
    bytes.push_back(0);
    return bytes;
}
Bytes expected_roll(std::uint8_t tile, std::uint8_t direction) {
    return {0x11,0x40,0x56,0x34,tile,0,1,1,1,0,0,static_cast<std::uint8_t>(0xa4U|direction),
        0xb6,0xc7,0xd8,0xe9,0xfa,0x8b,0x9c,0xad,0xbe,0xcf,0xd0,0xe1,0,0,0,0};
}
void open_shop(const Client& client) {
    client.send(ticket(direct_admission()));
    require(client.plain() == expected_init(),"tcp_shop_startup_init_wrong");
    client.send(message(Bytes{0,0}));
    require(client.plain() == expected_snapshot() && client.plain() == turn,"tcp_shop_startup_wrong");
    client.send(message(Bytes{16,0,0,0,0,0,0,0}));
    require(client.plain() == expected_roll(179,1),"tcp_shop_initial_roll_wrong");
    client.send(message(Bytes{17,0,0,0,178,0}));
    require(client.plain() == Bytes{0x13,0x40,0x56,0x34,178,0,0xfa,0xce},"tcp_shop_landing_wrong");
    require(client.plain() == expected_stock(),"tcp_shop_open_stock_wrong");
}
void expire_and_choose_fork(const Client& client, ShopEvidence& evidence) {
    evidence.seconds.fetch_add(10);
    require(client.plain() == Bytes{0x31,0x40,0x56,0x34,0xff},"tcp_shop_idle_timeout_did_not_close");
    const auto before = evidence.actions.load();
    client.send(message(Bytes{48,0,0,0,0xff,0xd3}));
    client.send(message(Bytes{52,0,0,0,2,0x93}));
    require(client.plain() == Bytes{0x35,0x40,0x56,0x34,2,0xbe,0xef},"tcp_shop_fork_after_timeout_wrong");
    require(client.plain() == turn,"tcp_shop_turn_after_fork_missing");
    require(evidence.actions.load() == before+1,"tcp_shop_late_current_context_exit_reached_strategy");
}

void idle_shop_closes_and_stale_exit_is_narrow(std::shared_ptr<const OriginalMapResources> map) {
    ShopEvidence evidence;
    Running running([&] { return direct_callbacks(plan(map,evidence)); });
    const auto port = running.service.bound_port();
    const Client survivor(port);
    open_shop(survivor);
    survivor.send(message(Bytes{48,0,0,0,0,0x71}));
    require(survivor.plain() == Bytes{0x31,0x40,0x56,0x34,0},"tcp_shop_buy_ack_wrong");
    require(evidence.tickets.load() == 470,"tcp_shop_buy_ticket_debit_wrong");
    survivor.send(message(Bytes{49,0,0,0,0,0x82}));
    require(survivor.plain() == Bytes{0x32,0x40,0x56,0x34,0},"tcp_shop_sale_ack_wrong");
    require(evidence.tickets.load() == 485,"tcp_shop_sale_ticket_refund_wrong");
    expire_and_choose_fork(survivor,evidence);

    for (const auto opcode : {std::uint8_t{48},std::uint8_t{49}}) {
        const Client stale(port);
        open_shop(stale);
        expire_and_choose_fork(stale,evidence);
        const auto before = evidence.actions.load();
        stale.send(message(Bytes{opcode,0,0,0,0,0xa7}));
        stale.closed();
        require(evidence.actions.load() == before,"tcp_shop_stale_transaction_reached_strategy");
    }
    const auto before = evidence.actions.load();
    auto late_exit = message(Bytes{48,0,0,0,0xff,0xe4});
    const auto roll = message(Bytes{16,0,1,0,0,0,0,0});
    late_exit.insert(late_exit.end(),roll.begin(),roll.end());
    survivor.send(late_exit);
    require(survivor.plain() == expected_roll(178,2),"tcp_shop_late_exit_changed_context_or_direction");
    require(evidence.actions.load() == before+1,"tcp_shop_stale_exit_not_ignored");
    survivor.send(message(Bytes{17,0,1,0,162,0}));
    require(survivor.plain() == Bytes{0x13,0x40,0x56,0x34,162,0,0xfa,0xce},"tcp_shop_post_fork_landing_wrong");
    require(survivor.plain() == turn,"tcp_shop_post_fork_turn_missing");
    survivor.send(message(Bytes{10,0})); survivor.closed();
    running.finish();
    require(evidence.closes.load() == 3 && evidence.turns.load() == 4,"tcp_shop_duplicate_close_or_turn");
    require(evidence.releases.load() == 3,"tcp_shop_session_cleanup_wrong");
}
}

int main() {
    try {
        const Network network;
        constexpr std::u8string_view source_path = RICHONLINE_LEGACY_RESOURCE_ROOT;
        const auto root = std::filesystem::path(std::u8string(source_path.begin(),source_path.end()));
        const auto map = std::make_shared<OriginalMapResources>(original_map_resources(
            load_original_emp(root / "Map" / "BS_1_1.emp"),10));
        require(std::find(map->edges.begin(),map->edges.end(),OriginalRoadEdge{179,178,1}) != map->edges.end() &&
            std::find(map->edges.begin(),map->edges.end(),OriginalRoadEdge{178,162,2}) != map->edges.end(),
            "tcp_shop_actual_map_edges_missing");
        idle_shop_closes_and_stale_exit_is_narrow(map);
        std::cout << "PASS original shop encrypted TCP idle timeout, buy/sell, fork and narrow stale-exit handling.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
