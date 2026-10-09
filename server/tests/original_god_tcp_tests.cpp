#include "original_game_startup_test_support.hpp"
#include "original_god_rewards.hpp"
#include "original_shop.hpp"
#include "original_wealth.hpp"
#include <iostream>

namespace {
using namespace original_startup_test;
struct Evidence {
    std::array<std::atomic_uint,3> cash{};
    std::atomic_uint actions{0}, settlements{0}, releases{0}, turns{0};
    std::atomic_bool pending{false}, owner_ack{false};
};
std::shared_ptr<OriginalShop> shop(std::uint16_t context, OriginalInventory inventory) {
    return std::make_shared<OriginalShop>(OriginalShopSetup{0x3456,context,0,OriginalShopClock::time_point{},5},
        OriginalShopCatalog{{1044,1038},{1044,1038},{{1044,30},{1038,40}},{{1044,1},{1038,1}}},
        std::make_shared<OriginalCardCombinations>(),OriginalShopWallet{inventory,200,100},[](std::uint32_t) { return 0U; });
}
void start(const Client& client, std::int16_t self = 25) {
    auto admission = direct_admission(); admission.id2 = static_cast<std::uint32_t>(self);
    client.send(ticket(admission));
    require(client.plain() == expected_init(static_cast<std::uint8_t>(self)),"god_tcp_init_wrong");
    client.send(message(Bytes{0,0}));
    require(client.plain() == expected_snapshot() && client.plain() == turn,"god_tcp_startup_wrong");
}
void no_packet(const Client& client) {
    fd_set readable; FD_ZERO(&readable); FD_SET(client.socket,&readable);
    timeval timeout{0,150000};
    require(select(0,&readable,nullptr,nullptr,&timeout) == 0,"god_tcp_unexpected_automatic_continuation");
}
struct WealthFixture {
    OriginalWealthSettlement wealth;
    OriginalWealthSnapshot snapshot;
    std::shared_ptr<Evidence> evidence;
    std::shared_ptr<OriginalShop> inventory_shop;
    explicit WealthFixture(std::shared_ptr<Evidence> observed, bool bankruptcy)
        : snapshot{0,0,{{{bankruptcy ? 20U : 1000U,bankruptcy ? 10U : 0U,200},1,true,static_cast<std::int8_t>(bankruptcy ? 1 : 0)},
            {{200,0,200},1,true,-1},{{300,0,200},2,true,-1}}},evidence(std::move(observed)) {
        wealth.begin({0,0,snapshot.players[0].god,OriginalWealthOrigin::card});
        for (std::size_t i = 0; i < 3; ++i) evidence->cash[i].store(snapshot.players[i].funds.cash);
    }
    void open_inventory_shop() {
        inventory_shop = shop(snapshot.context,add_original_card(make_original_inventory(),1044,1).inventory);
    }
    std::vector<Bytes> action(View plain) {
        ++evidence->actions;
        if (read_le(plain.first(2)) == 34) {
            auto result = wealth.resolve(parse_original_wealth_choice(plain),snapshot,90);
            snapshot.players = result.players;
            for (std::size_t i = 0; i < 3; ++i) evidence->cash[i].store(result.players[i].funds.cash);
            ++evidence->settlements; evidence->pending.store(wealth.pending().has_value());
            if (!result.bankruptcy_wait) {
                require(result.continuation == OriginalWealthContinuation::card,"god_tcp_origin_lost");
                open_inventory_shop();
            }
            return {encode_original_wealth_result(0x3456,result.amount,result.bankruptcy_wait)};
        }
        require(inventory_shop != nullptr,"god_tcp_action_before_owner_completion");
        const auto result = inventory_shop->handle(parse_original_shop_request(plain),OriginalShopClock::time_point{});
        require(!result.rejection,"god_tcp_inventory_action_rejected");
        return result.messages;
    }
    std::vector<Bytes> poll() {
        if (!evidence->owner_ack.exchange(false)) return {};
        require(wealth.awaiting_bankruptcy() && wealth.pending().has_value(),"god_tcp_owner_ack_without_wait");
        require(wealth.finish_bankruptcy(snapshot.context) == OriginalWealthContinuation::card,"god_tcp_owner_completion_origin_wrong");
        evidence->pending.store(false); ++snapshot.context; ++evidence->turns;
        open_inventory_shop(); return {turn};
    }
};
OriginalGamePlan wealth_plan(std::shared_ptr<Evidence> evidence, std::int16_t self, bool bankruptcy) {
    // Startup, settlement amount, shop handoff and owner acknowledgment are explicit test strategy policy.
    auto fixture = std::make_shared<WealthFixture>(std::move(evidence),bankruptcy);
    return {startup(self),[] { return std::vector<Bytes>{turn}; },
        [fixture](View plain) { return fixture->action(plain); },[fixture] { ++fixture->evidence->releases; },
        [fixture] { return fixture->poll(); }};
}
void wealth_context_isolation_and_owner_wait() {
    std::array<std::shared_ptr<Evidence>,3> evidence;
    for (auto& item : evidence) item = std::make_shared<Evidence>();
    unsigned next = 0;
    Running running([&] {
        const auto index = next++;
        return direct_callbacks(wealth_plan(evidence.at(index),static_cast<std::int16_t>(25+index),index == 2));
    });
    const Client normal(running.service.bound_port()); start(normal);
    const Client wrong(running.service.bound_port()); start(wrong,26);
    wrong.send(message(Bytes{34,0,1,0,1,0x91})); wrong.closed();
    require(evidence[1]->actions.load() == 0 && evidence[1]->cash[0].load() == 1000,"god_tcp_wrong_context_mutated_money");
    normal.send(message(Bytes{34,0,0,0,1,0x82}));
    require(normal.plain() == Bytes{0x22,0x40,0x56,0x34,90,0,0},"god_tcp_wealth_result_wrong");
    require(evidence[0]->cash[0].load() == 1090 && evidence[0]->cash[1].load() == 200 &&
        evidence[0]->cash[2].load() == 210,"god_tcp_team_distribution_wrong");
    normal.send(message(Bytes{49,0,0,0,0,0x73}));
    require(normal.plain() == Bytes{0x32,0x40,0x56,0x34,0},"god_tcp_wealth_changed_context");
    normal.send(message(Bytes{34,0,0,0,1,0x64})); normal.closed();
    require(evidence[0]->settlements.load() == 1 && evidence[0]->cash[0].load() == 1090 && evidence[0]->cash[2].load() == 210,
        "god_tcp_duplicate_wealth_charged_twice");
    const Client bankrupt(running.service.bound_port()); start(bankrupt,27);
    bankrupt.send(message(Bytes{34,0,0,0,1,0x55}));
    require(bankrupt.plain() == Bytes{0x22,0x40,0x56,0x34,90,0,1},"god_tcp_bankruptcy_wait_flag_wrong");
    require(evidence[2]->pending.load() && evidence[2]->turns.load() == 0 && evidence[2]->cash[0].load() == 0 &&
        evidence[2]->cash[1].load() == 245 && evidence[2]->cash[2].load() == 345,"god_tcp_bankruptcy_state_wrong");
    no_packet(bankrupt);
    evidence[2]->owner_ack.store(true);
    require(bankrupt.plain() == turn,"god_tcp_explicit_owner_completion_missing");
    require(!evidence[2]->pending.load() && evidence[2]->turns.load() == 1,"god_tcp_owner_completion_not_once");
    bankrupt.send(message(Bytes{49,0,1,0,0,0x46}));
    require(bankrupt.plain() == Bytes{0x32,0x40,0x56,0x34,0},"god_tcp_post_bankruptcy_context_wrong");
    bankrupt.send(message(Bytes{10,0})); bankrupt.closed(); running.finish();
    for (const auto& item : evidence) require(item->releases.load() == 1,"god_tcp_cleanup_wrong");
}
void blessing_rewards_are_real_inventory() {
    auto inventory = std::make_shared<OriginalInventory>(make_original_inventory());
    std::shared_ptr<OriginalShop> inventory_shop;
    Running running([&] {
        return direct_callbacks({startup(),[&] {
            const auto result = grant_original_blessing(*inventory,0x3456,{1044,1038},{},std::array<std::int16_t,2>{1044,1038});
            *inventory = result.inventory; inventory_shop = shop(0,*inventory);
            require(result.slots[0] == 0 && result.slots[1] == 1,"god_tcp_blessing_slots_wrong");
            return std::vector<Bytes>{turn,result.message,inventory_shop->open_message()};
        },[&](View plain) {
            const auto result = inventory_shop->handle(parse_original_shop_request(plain),OriginalShopClock::time_point{});
            require(!result.rejection,"god_tcp_blessing_inventory_action_rejected");
            return result.messages;
        },[] {}});
    });
    const Client client(running.service.bound_port()); start(client);
    require(client.plain() == Bytes{0x23,0x40,0x56,0x34,0x14,4,0x0e,4},"god_tcp_blessing_ids_wrong");
    const auto stock = client.plain(); require(stock.size() == 77 && stock[0] == 0x30 && stock[1] == 0x40,"god_tcp_blessing_shop_missing");
    client.send(message(Bytes{49,0,0,0,0,0x37}));
    require(client.plain() == Bytes{0x32,0x40,0x56,0x34,0},"god_tcp_blessing_sale_failed");
    client.send(message(Bytes{50,0,0,0,1,0x28}));
    require(client.plain() == Bytes{0x33,0x40,0x56,0x34,1,0},"god_tcp_blessing_discard_failed");
    client.send(message(Bytes{10,0})); client.closed(); running.finish();
    require(inventory_shop->wallet().inventory[0].id == -1 && inventory_shop->wallet().inventory[1].id == -1 &&
        inventory_shop->wallet().tickets == 215,"god_tcp_blessing_inventory_accounting_wrong");
}
void full_bag_and_stacked_misfortune() {
    OriginalInventory inventory;
    inventory.fill({1044,5,{0x91,0xe2}});
    Running running([&] {
        return direct_callbacks({startup(),[&] {
            auto result = grant_original_blessing(inventory,0x3456,{1044,1038},{},std::array<std::int16_t,2>{1044,1038});
            require(!result.slots[0] && !result.slots[1] && result.inventory == inventory,"god_tcp_fullbag_changed_inventory");
            auto misfortune = apply_original_misfortune(result.inventory,0x3456,{0,0,0,-1});
            inventory = misfortune.inventory;
            return std::vector<Bytes>{turn,result.message,misfortune.message};
        },[](View) -> std::vector<Bytes> { throw CodecError("god_tcp_unexpected_fullbag_action"); },[] {}});
    });
    const Client client(running.service.bound_port()); start(client);
    require(client.plain() == Bytes{0x23,0x40,0x56,0x34,0x14,4,0x0e,4},"god_tcp_fullbag_reward_ids_lost");
    require(client.plain() == Bytes{0x24,0x40,0x56,0x34,0,0,0,0xff},"god_tcp_misfortune_slots_wrong");
    client.send(message(Bytes{10,0})); client.closed(); running.finish();
    require(inventory[0] == OriginalCardSlot{1044,2,{0x91,0xe2}} && inventory[1] == OriginalCardSlot{1044,5,{0x91,0xe2}},
        "god_tcp_misfortune_stack_or_tail_wrong");
}
}
int main() {
    try {
        const Network network;
        wealth_context_isolation_and_owner_wait(); blessing_rewards_are_real_inventory(); full_bag_and_stacked_misfortune();
        std::cout << "PASS original god encrypted TCP settlements, explicit bankruptcy wait, rewards and inventory effects.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
