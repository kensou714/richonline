#include "original_game_startup_test_support.hpp"
#include "original_god_event.hpp"
#include "original_god_resources.hpp"
#include "original_property.hpp"
#include "original_shop.hpp"
#include <iostream>

namespace {
using namespace original_startup_test;
struct PyramidInput {
    std::shared_ptr<const OriginalMapResources> map;
    OriginalBuildingPolicy policy;
    OriginalGodRules gods;
    std::int16_t tile;
    std::int8_t level;
    bool friendly;
};
struct Evidence {
    std::atomic_uint completions{0}, settlements{0}, releases{0}, actor_cash{1000}, enemy_cash{500};
    std::atomic_bool waiting{false};
};
struct Fixture {
    PyramidInput input;
    OriginalBossProperties properties;
    OriginalPropertyActor actor{{1000,0,200},make_original_inventory(),{7,7,7,7,7,7,7,7,7,7},false,false,false,false,false};
    std::optional<OriginalGodEvent> event;
    std::optional<OriginalShop> shop;
    OriginalWealthSnapshot snapshot{0,0,{{{1000,0,200},1,true,-1},{{500,0,200},2,true,-1}}};
    std::shared_ptr<Evidence> evidence;
    Fixture(PyramidInput setup, std::shared_ptr<Evidence> observations)
        : input(std::move(setup)),properties(0x3456,input.map,input.policy),evidence(std::move(observations)) {
        actor.inventory[0] = {1044,3,{0x91,0xe2}};
    }
    void finish_property() {
        require(event->finish() == OriginalGodOrigin::property,"pyramid_tcp_wrong_completion_origin");
        properties.complete_pyramid(0);
        require(properties.stage() == OriginalPropertyStage::complete,"pyramid_tcp_property_still_pending");
        evidence->waiting.store(false); ++evidence->completions;
        shop.emplace(OriginalShopSetup{0x3456,0,0,OriginalShopClock::time_point{},5},
            OriginalShopCatalog{{1044,1038},{1044,1038},{{1044,30},{1038,40}},{{1044,1},{1038,1}}},
            std::make_shared<OriginalCardCombinations>(),OriginalShopWallet{actor.inventory,actor.funds.tickets,100},
            [](std::uint32_t) { return 0U; });
    }
    std::vector<Bytes> open() {
        require(properties.begin({0,0,input.tile,input.friendly},actor) == OriginalPropertyStage::pyramid,
            "pyramid_tcp_cap_or_enemy_waited_for_upgrade");
        const auto transition = apply_original_pyramid({-1,-1,0,0,1.0F},input.level,input.friendly,false,input.gods);
        event.emplace(OriginalGodEventSetup{0x3456,0,0,transition});
        snapshot.players[0].god = transition.state.kind;
        evidence->waiting.store(true);
        std::vector<Bytes> messages{turn};
        if (input.level == 6 && input.friendly) {
            require(transition.state.kind == 3 && transition.wait == OriginalGodWait::blessing,"pyramid_tcp_friendly_summon_wrong");
            const auto reward = event->bless(actor.inventory,{1044,1038},{},std::array<std::int16_t,2>{1044,1038});
            actor.inventory = reward.inventory; messages.push_back(reward.message);
            require(actor.inventory[1].id == 1044 && actor.inventory[2].id == 1038,"pyramid_tcp_reward_not_inventory");
            finish_property();
        } else if (input.level == 6) {
            require(transition.state.kind == 2 && transition.wait == OriginalGodWait::misfortune_cards,"pyramid_tcp_enemy_summon_wrong");
            const auto loss = event->discard(actor.inventory,{0,-1,-1,-1});
            actor.inventory = loss.inventory; messages.push_back(loss.message);
            require(actor.inventory[0] == OriginalCardSlot{1044,2,{0x91,0xe2}},"pyramid_tcp_misfortune_stack_wrong");
            finish_property();
        } else {
            require(transition.state.kind == (input.friendly ? 0 : 1) && transition.wait == OriginalGodWait::wealth,
                "pyramid_tcp_level7_wealth_wait_missing");
        }
        return messages;
    }
    std::vector<Bytes> action(View plain) {
        if (read_le(plain.first(2)) == 34) {
            const auto result = event->settle(parse_original_wealth_choice(plain),snapshot,90);
            require(!result.bankruptcy_wait && result.continuation == OriginalWealthContinuation::property,
                "pyramid_tcp_wealth_continuation_wrong");
            snapshot.players = result.players; actor.funds = result.players[0].funds;
            evidence->actor_cash.store(result.players[0].funds.cash); evidence->enemy_cash.store(result.players[1].funds.cash);
            ++evidence->settlements;
            finish_property();
            return {encode_original_wealth_result(0x3456,result.amount,result.bankruptcy_wait)};
        }
        require(shop.has_value(),"pyramid_tcp_shop_before_property_completion");
        const auto result = shop->handle(parse_original_shop_request(plain),OriginalShopClock::time_point{});
        require(!result.rejection,"pyramid_tcp_reward_sale_failed");
        return result.messages;
    }
};
PyramidInput setup(const std::filesystem::path& root, std::int8_t level, bool friendly) {
    auto map = std::make_shared<OriginalMapResources>(original_map_resources(load_original_emp(root/"Map"/"BS_2_1.emp"),10));
    const auto road = std::find_if(map->roads.begin(),map->roads.end(),[](const auto& cell) { return cell.property_id >= 0; });
    require(road != map->roads.end(),"pyramid_tcp_original_road_missing");
    const auto property = std::find_if(map->properties.begin(),map->properties.end(),[&](const auto& item) { return item.id == road->property_id; });
    require(property != map->properties.end(),"pyramid_tcp_original_property_missing");
    // Existing pyramid ownership/level, level-seven cap and shop handoff are explicit test fixtures, not EMP defaults.
    property->kind = 16; property->level = level; property->owner = friendly ? 0 : 1;
    const auto policies = load_original_building_policies(root/"Data"/"BossWar.kpd");
    const auto found = std::find_if(policies.maps.begin(),policies.maps.end(),[](const auto& item) { return item.map_name == "BS_2_1.emp"; });
    require(found != policies.maps.end() && found->default_kind.has_value() && found->level_caps[5] == 6,"pyramid_tcp_original_cap_wrong");
    OriginalBuildingPolicy policy{*found->default_kind,found->level_caps};
    if (level == 7) policy.level_caps[5] = 7;
    const auto rules = original_god_rules(load_original_npc_resources(root/"Data"/"Npc.kpd"),
        load_original_research_resources(root/"Data"/"BwbValue.kpd"),load_original_game_values(root/"Data"/"GValue.kpd"));
    return {map,policy,rules,road->tile,level,friendly};
}
void pyramid_flow(PyramidInput input) {
    const auto level = input.level; const auto friendly = input.friendly;
    auto evidence = std::make_shared<Evidence>();
    Running running([&] {
        auto fixture = std::make_shared<Fixture>(input,evidence);
        return direct_callbacks({startup(),[fixture] { return fixture->open(); },
            [fixture](View plain) { return fixture->action(plain); },[fixture] { ++fixture->evidence->releases; }});
    });
    const Client client(running.service.bound_port());
    client.send(ticket(direct_admission())); require(client.plain() == expected_init(),"pyramid_tcp_init_wrong");
    client.send(message(Bytes{0,0}));
    require(client.plain() == expected_snapshot() && client.plain() == turn,"pyramid_tcp_startup_wrong");
    if (level == 6) {
        const Bytes expected = friendly ? Bytes{0x23,0x40,0x56,0x34,0x14,4,0x0e,4} : Bytes{0x24,0x40,0x56,0x34,0,0xff,0xff,0xff};
        require(client.plain() == expected,"pyramid_tcp_immediate_god_followup_wrong");
    } else {
        require(evidence->waiting.load() && evidence->completions.load() == 0,"pyramid_tcp_wealth_completed_early");
        client.send(message(Bytes{34,0,0,0,1,0x97}));
        require(client.plain() == Bytes{0x22,0x40,0x56,0x34,90,0,0},"pyramid_tcp_wealth_reply_wrong");
        require(evidence->actor_cash.load() == (friendly ? 1090U : 910U) && evidence->enemy_cash.load() == (friendly ? 410U : 590U),
            "pyramid_tcp_wealth_distribution_wrong");
    }
    require(!evidence->waiting.load() && evidence->completions.load() == 1,"pyramid_tcp_property_not_completed_once");
    client.send(message(Bytes{49,0,0,0,static_cast<std::uint8_t>(level == 6 && friendly ? 1 : 0),0x86}));
    require(client.plain() == Bytes{0x32,0x40,0x56,0x34,static_cast<std::uint8_t>(level == 6 && friendly ? 1 : 0)},
        "pyramid_tcp_context_changed_or_unexpected_resume_packet");
    if (level == 7) {
        client.send(message(Bytes{34,0,0,0,1,0x75})); client.closed();
        require(evidence->settlements.load() == 1 && evidence->completions.load() == 1,"pyramid_tcp_duplicate_reapplied_effect");
    } else { client.send(message(Bytes{10,0})); client.closed(); }
    running.finish(); require(evidence->releases.load() == 1,"pyramid_tcp_cleanup_wrong");
}
}
int main() {
    try {
        const Network network;
        constexpr std::u8string_view source = RICHONLINE_LEGACY_RESOURCE_ROOT;
        const auto root = std::filesystem::path(std::u8string(source.begin(),source.end()));
        for (const auto level : {std::int8_t{6},std::int8_t{7}})
            for (const auto friendly : {true,false}) pyramid_flow(setup(root,level,friendly));
        std::cout << "PASS original pyramid encrypted TCP native property and god-event continuation.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
