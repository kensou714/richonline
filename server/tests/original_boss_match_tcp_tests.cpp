#include "original_boss_match_test_support.hpp"
#include <iostream>

namespace {
using namespace original_boss_match_test;
Bytes turn_message(std::uint8_t slot) { return {0x10,0x40,0x56,0x34,slot,1,0,0xd1}; }
const Bytes resume{0x0f,0x42,0x56,0x34,0xff,0xff,0xd2};
Bytes initial_cards(std::uint8_t owner) {
    Bytes bytes{0x19,0x40,0x56,0x34,owner,0};
    const std::array<std::int16_t,4> cards = owner == 0 ? std::array<std::int16_t,4>{1038,1044,-1,-1} :
        std::array<std::int16_t,4>{-1,-1,-1,-1};
    for (const auto card : cards) {
        append_le(bytes,static_cast<std::uint16_t>(card),2); append_le(bytes,card == -1 ? 0U : 1U,2);
        bytes.insert(bytes.end(),{0,0xff});
    }
    bytes.push_back(0xd3); return bytes;
}
void startup_boss(const Client& client, const Fixture& fixture, std::uint8_t direction = 3) {
    client.send(ticket(direct_admission()));
    require(client.plain() == encode_original_board_init(fixture.expected_startup.init),"boss_match_tcp_init_wrong");
    client.send(message(Bytes{0,0}));
    require(client.plain() == encode_original_board_snapshot(fixture.expected_startup.snapshot),"boss_match_tcp_snapshot_wrong");
    require(client.plain() == initial_cards(0) && client.plain() == initial_cards(1),"boss_match_tcp_initial_inventory_wrong");
    require(client.plain() == turn_message(1) && client.plain() == resume,"boss_match_tcp_boss_first_turn_wrong");
    require(client.plain() == roll(123,direction),"boss_match_tcp_boss_did_not_auto_roll");
}
void reach_shop(const Client& client, std::uint8_t boss_tile = 124) {
    client.send(message(Bytes{17,0,0,0,boss_tile,0}));
    require(client.plain() == Bytes{0x13,0x40,0x56,0x34,boss_tile,0,0xfa,0xce},"boss_match_tcp_boss_landing_wrong");
    require(client.plain() == turn_message(0) && client.plain() == resume,"boss_match_tcp_human_turn_wrong");
    no_packet(client);
    client.send(message(Bytes{16,0,1,0,0,0,0,0}));
    require(client.plain() == roll(179,1),"boss_match_tcp_human_roll_wrong");
    client.send(message(Bytes{17,0,1,0,178,0}));
    require(client.plain() == Bytes{0x13,0x40,0x56,0x34,178,0,0xfa,0xce},"boss_match_tcp_human_landing_wrong");
    const auto stock = client.plain();
    require(stock.size() == 77 && read_le(View(stock).first(2)) == 0x4030 &&
        read_le(View(stock).subspan(2,2)) == 0x3456 && stock.back() == 0,"boss_match_tcp_shop_not_open");
}
void shop_exit_and_fork(bool timeout) {
    Fixture fixture({179,1},{123,3});
    Running running([&] { return callbacks(fixture); });
    const Client client(running.service.bound_port()); startup_boss(client,fixture); reach_shop(client);
    no_packet(client);
    if (timeout) fixture.seconds.store(10);
    else client.send(message(Bytes{48,0,1,0,0xff,0x71}));
    require(client.plain() == Bytes{0x31,0x40,0x56,0x34,0xff},"boss_match_tcp_shop_exit_missing");
    no_packet(client);
    client.send(message(Bytes{52,0,1,0,2,0x82}));
    require(client.plain() == Bytes{0x35,0x40,0x56,0x34,2,0xbe,0xef},"boss_match_tcp_fork_context_or_direction_wrong");
    require(client.plain() == turn_message(1) && client.plain() == resume,"boss_match_tcp_next_boss_turn_wrong");
    require(client.plain() == roll(124,3),"boss_match_tcp_next_boss_roll_wrong");
    auto next = message(Bytes{48,0,1,0,0xff,0x93});
    const auto landed = message(Bytes{17,0,2,0,125,0});
    next.insert(next.end(),landed.begin(),landed.end()); client.send(next);
    require(client.plain() == Bytes{0x13,0x40,0x56,0x34,125,0,0xfa,0xce},"boss_match_tcp_late_shop_exit_broke_new_context");
    require(client.plain() == turn_message(0) && client.plain() == resume,"boss_match_tcp_second_human_turn_wrong");
    client.send(message(Bytes{10,0}));
    running.finish();
    require(fixture.match->phase() == OriginalBossMatchPhase::closed,"boss_match_tcp_shutdown_not_closed");
}
void human_cannot_roll_for_boss() {
    Fixture fixture;
    Running running([&] { return callbacks(fixture); });
    const Client client(running.service.bound_port()); startup_boss(client,fixture,1);
    client.send(message(Bytes{16,0,0,0,0,0,0,0})); client.closed(); running.finish();
    require(fixture.match->phase() == OriginalBossMatchPhase::closed,"boss_match_tcp_invalid_roll_not_closed");
}
void unsupported_landing_is_explicit() {
    Fixture fixture;
    Running running([&] { return callbacks(fixture); });
    const Client client(running.service.bound_port()); startup_boss(client,fixture,1); reach_shop(client,122);
    client.send(message(Bytes{48,0,1,0,0xff,0x71}));
    require(client.plain() == Bytes{0x31,0x40,0x56,0x34,0xff},"boss_match_tcp_unsupported_fixture_shop_exit");
    client.send(message(Bytes{52,0,1,0,2,0x82}));
    require(client.plain() == Bytes{0x35,0x40,0x56,0x34,2,0xbe,0xef} && client.plain() == turn_message(1) &&
        client.plain() == resume && client.plain() == roll(122,1),"boss_match_tcp_unsupported_fixture_next_turn");
    client.send(message(Bytes{17,0,2,0,121,0})); client.closed(); running.finish();
    const std::lock_guard lock(fixture.diagnostic_mutex);
    require(fixture.request_failure == "original_boss_match_tile_unimplemented type=70 tile=121 context=305463298",
        "boss_match_tcp_unknown_landing_was_silently_skipped");
}
Bytes expired_shop_requests() {
    Bytes batch;
    for (const auto& plain : {Bytes{48,0,1,0,0,0xa1},Bytes{49,0,1,0,0,0xb2},
        Bytes{50,0,1,0,0,0xc3},Bytes{53,0,1,0}}) {
        const auto frame = message(plain); batch.insert(batch.end(),frame.begin(),frame.end());
    }
    return batch;
}
void expired_shop_actions_preserve_pending_turn(bool after_direction) {
    Fixture fixture({179,1},{123,3});
    const auto original_inventory = fixture.match->actor(0).inventory;
    const auto original_funds = fixture.match->actor(0).funds;
    Running running([&] { return callbacks(fixture); });
    const Client client(running.service.bound_port()); startup_boss(client,fixture); reach_shop(client);
    fixture.seconds.store(10);
    require(client.plain() == Bytes{0x31,0x40,0x56,0x34,0xff},"boss_match_tcp_expired_shop_did_not_close");
    auto choice = message(Bytes{52,0,1,0,2,0x82});
    if (!after_direction) {
        auto batch = expired_shop_requests(); batch.insert(batch.end(),choice.begin(),choice.end());
        client.send(batch);
    } else client.send(choice);
    require(client.plain() == Bytes{0x35,0x40,0x56,0x34,2,0xbe,0xef},"boss_match_tcp_expired_actions_broke_fork");
    require(client.plain() == turn_message(1) && client.plain() == resume && client.plain() == roll(124,3),
        "boss_match_tcp_expired_actions_duplicated_next_turn");
    auto batch = after_direction ? expired_shop_requests() : Bytes{};
    const auto arrival = message(Bytes{17,0,2,0,125,0});
    batch.insert(batch.end(),arrival.begin(),arrival.end()); client.send(batch);
    require(client.plain() == Bytes{0x13,0x40,0x56,0x34,125,0,0xfa,0xce} &&
        client.plain() == turn_message(0) && client.plain() == resume,"boss_match_tcp_expired_actions_broke_new_context");
    client.send(message(Bytes{10,0})); client.closed(); running.finish();
    const auto& actor = fixture.match->actor(0);
    require(actor.inventory == original_inventory && actor.funds.cash == original_funds.cash &&
        actor.funds.deposit == original_funds.deposit && actor.funds.tickets == original_funds.tickets,
        "boss_match_tcp_expired_actions_changed_wallet_or_inventory");
}
}
int main(int argc, char** argv) {
    try {
        const Network network;
        if (argc == 2) {
            const std::string_view scenario = argv[1];
            require(scenario == "expired-before-fork" || scenario == "expired-after-fork","boss_match_tcp_unknown_scenario");
            expired_shop_actions_preserve_pending_turn(scenario == "expired-after-fork");
            std::cout << "PASS " << scenario << '\n'; return 0;
        }
        shop_exit_and_fork(false); shop_exit_and_fork(true); human_cannot_roll_for_boss(); unsupported_landing_is_explicit();
        expired_shop_actions_preserve_pending_turn(false); expired_shop_actions_preserve_pending_turn(true);
        std::cout << "PASS native BOSS match encrypted TCP scheduling, shop exit/timeout and fork; attacks explicitly disabled in fixture.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
