#include "original_game_startup_test_support.hpp"
#include "original_property.hpp"
#include "original_shop.hpp"
#include <iostream>

namespace {
using namespace original_startup_test;
enum class Scenario { research, miracle, skill_limit };
OriginalBuildingPolicy building_policy() {
    constexpr std::u8string_view source = RICHONLINE_LEGACY_RESOURCE_ROOT;
    const auto root = std::filesystem::path(std::u8string(source.begin(),source.end()));
    const auto policies = load_original_building_policies(root/"Data"/"BossWar.kpd");
    const auto found = std::find_if(policies.maps.begin(),policies.maps.end(),[](const auto& item) { return item.map_name == "BS_1_1.emp"; });
    require(found != policies.maps.end() && found->default_kind.has_value(),"property_original_policy_missing");
    return {*found->default_kind,found->level_caps};
}
struct Evidence {
    std::atomic_uint cash{100000}, tickets{200}, actions{0}, turns{0}, releases{0}, grants{0};
    std::atomic_int stage{0}, kind{0}, level{0}, license_count{0}, remaining_cards{0};
};
struct Fixture {
    OriginalBossProperties properties;
    OriginalResearchQueue research;
    OriginalPropertyActor actor;
    std::optional<OriginalShop> shop;
    std::shared_ptr<const OriginalCardCombinations> combinations = std::make_shared<OriginalCardCombinations>();
    std::shared_ptr<Evidence> evidence;
    Scenario scenario;
    std::uint16_t context = 0;
    Fixture(std::shared_ptr<const OriginalMapResources> map, std::array<OriginalResearchChoice,7> choices,
        std::shared_ptr<Evidence> observations, Scenario mode)
        : properties(0x3456,std::move(map),building_policy()),research(choices),
          actor{{100000,0,200},make_original_inventory(),{7,7,7,7,7,7,7,7,7,7},false,false,false,false,false},
          evidence(std::move(observations)),scenario(mode) {
        if (scenario == Scenario::miracle) actor.inventory = add_original_card(actor.inventory,511,1).inventory;
        if (scenario == Scenario::skill_limit) actor.skills[0] = 1;
    }
    void record() {
        evidence->cash.store(actor.funds.cash); evidence->tickets.store(actor.funds.tickets);
        evidence->stage.store(static_cast<int>(properties.stage()));
        const auto& records = properties.records();
        const auto property = std::find_if(records.begin(),records.end(),[](const auto& item) { return item.id == 104; });
        require(property != records.end(),"property_fixture_record_missing");
        evidence->kind.store(property->kind); evidence->level.store(property->level);
        int licenses = 0, cards = 0;
        for (const auto& slot : actor.inventory) {
            if (slot.id == 511) licenses += slot.count;
            if (slot.id >= 0) ++cards;
        }
        evidence->license_count.store(licenses); evidence->remaining_cards.store(cards);
    }
    std::vector<Bytes> open() {
        require(properties.begin({context,0,119,false},actor) == OriginalPropertyStage::purchase,"property_fixture_purchase_missing");
        record(); return {turn};
    }
    void grant_research(std::vector<Bytes>& replies) {
        OriginalResearchInventories inventories;
        inventories.fill(make_original_inventory()); inventories[0] = actor.inventory;
        const std::array<std::int16_t,1> outputs{1044};
        for (int day = 0; day < 2; ++day) {
            auto advanced = research.advance(0,properties.records(),{inventories,*combinations,outputs});
            inventories = std::move(advanced.inventories);
            for (const auto& item : advanced.completed) {
                require(item.card_slot.has_value() && item.job.card == 1044,"property_research_grant_invalid");
                ++evidence->grants;
            }
        }
        actor.inventory = inventories[0];
        shop.emplace(OriginalShopSetup{0x3456,context,0,OriginalShopClock::time_point{},5},
            OriginalShopCatalog{{1044},{1044},{{1044,30}},{{1044,1}}},combinations,
            OriginalShopWallet{actor.inventory,actor.funds.tickets,100},[](std::uint32_t) { return 0U; });
        replies.push_back(shop->open_message());
    }
    std::vector<Bytes> action(View plain) {
        ++evidence->actions;
        const auto opcode = read_le(plain.first(2));
        if (opcode == 48 || opcode == 49 || opcode == 50) {
            require(shop.has_value(),"property_fixture_shop_not_open");
            auto result = shop->handle(parse_original_shop_request(plain),OriginalShopClock::time_point{});
            require(!result.rejection,"property_fixture_shop_rejected");
            actor.inventory = shop->wallet().inventory; actor.funds.tickets = shop->wallet().tickets;
            if (result.closed) { ++context; ++evidence->turns; result.messages.push_back(turn); }
            record(); return result.messages;
        }
        auto result = properties.handle(parse_original_property_request(plain),actor,research);
        actor = std::move(result.actor);
        std::vector<Bytes> replies{std::move(result.message)};
        if (opcode == 57 && scenario == Scenario::research) {
            require(result.research_jobs.size() == 3,"property_research_jobs_missing");
            grant_research(replies);
        } else if (result.stage == OriginalPropertyStage::complete) {
            ++context; ++evidence->turns;
            // Repeated landings, day advancement and shop prices are test scheduling only.
            if (opcode == 32 || (opcode == 55 && scenario != Scenario::miracle))
                properties.begin({context,0,119,false},actor);
            replies.push_back(turn);
        }
        record(); return replies;
    }
};
OriginalGamePlan make_plan(std::shared_ptr<Fixture> fixture) {
    return {startup(),[fixture] { return fixture->open(); },
        [fixture](View plain) {
            try { return fixture->action(plain); }
            catch (const std::exception& error) {
                std::cerr << "property_fixture_action_failed opcode=" << read_le(plain.first(2))
                    << " context=" << fixture->context << " reason=" << error.what() << '\n';
                throw;
            }
        },[fixture] { ++fixture->evidence->releases; }};
}
void start(const Client& client) {
    client.send(ticket(direct_admission())); require(client.plain() == expected_init(),"property_init_wrong");
    client.send(message(Bytes{0,0}));
    require(client.plain() == expected_snapshot() && client.plain() == turn,"property_startup_wrong");
}
Bytes purchase(std::uint16_t context) {
    return {32,0,static_cast<std::uint8_t>(context),static_cast<std::uint8_t>(context>>8),0,0,0,0,1,0x81,0x92,0xa3};
}
void buy_land(const Client& client) {
    client.send(message(purchase(0)));
    require(client.plain() == Bytes{0x20,0x40,0x56,0x34,1} && client.plain() == turn,"property_purchase_or_next_turn_wrong");
}
void build(const Client& client, std::uint8_t kind) {
    client.send(message(Bytes{55,0,1,0,kind,0xb4}));
    require(client.plain() == Bytes{0x3d,0x40,0x56,0x34,kind} && client.plain() == turn,"property_build_or_next_turn_wrong");
}
void research_and_isolation(std::shared_ptr<const OriginalMapResources> map,
    std::array<OriginalResearchChoice,7> choices, std::uint32_t price) {
    std::array<std::shared_ptr<Evidence>,3> evidence;
    for (auto& item : evidence) item = std::make_shared<Evidence>();
    unsigned connection = 0;
    Running running([&] { return direct_callbacks(make_plan(std::make_shared<Fixture>(map,choices,evidence.at(connection++),Scenario::research))); });
    const Client survivor(running.service.bound_port()); start(survivor); buy_land(survivor);
    {
        const Client wrong(running.service.bound_port()); start(wrong);
        wrong.send(message(purchase(1))); wrong.closed();
        require(evidence[1]->cash.load() == 100000 && evidence[1]->actions.load() == 0,"property_wrong_context_mutated_cash");
    }
    {
        const Client replay(running.service.bound_port()); start(replay); buy_land(replay);
        replay.send(message(purchase(0))); replay.closed();
        require(evidence[2]->cash.load() == 100000-price && evidence[2]->actions.load() == 1,"property_replay_debited_twice");
    }
    build(survivor,11);
    survivor.send(message(Bytes{56,0,2,0,0,0xc5}));
    require(survivor.plain() == Bytes{0x3e,0x40,0x56,0x34,0},"property_upgrade_decline_reply_wrong");
    require(evidence[0]->stage.load() == static_cast<int>(OriginalPropertyStage::research),"property_decline_skipped_research");
    survivor.send(message(Bytes{57,0,2,0,1,0xd6}));
    require(survivor.plain() == Bytes{0x3f,0x40,0x56,0x34,1},"property_research_choice_wrong");
    const auto stock = survivor.plain();
    require(stock.size() == 77 && read_le(View(stock).first(2)) == 0x4030,"property_research_shop_missing");
    survivor.send(message(Bytes{49,0,2,0,0,0xe7}));
    require(survivor.plain() == Bytes{0x32,0x40,0x56,0x34,0},"property_researched_card_sale_failed");
    survivor.send(message(Bytes{50,0,2,0,1,0xf8}));
    require(survivor.plain() == Bytes{0x33,0x40,0x56,0x34,1,0},"property_researched_card_discard_failed");
    survivor.send(message(Bytes{48,0,2,0,0xff,0xa9}));
    require(survivor.plain() == Bytes{0x31,0x40,0x56,0x34,0xff} && survivor.plain() == turn,"property_research_shop_close_failed");
    survivor.send(message(Bytes{10,0})); survivor.closed(); running.finish();
    require(evidence[0]->cash.load() == 100000-price && evidence[0]->tickets.load() == 215 &&
        evidence[0]->grants.load() == 2 && evidence[0]->remaining_cards.load() == 0 && evidence[0]->turns.load() == 3,
        "property_final_accounting_wrong");
    for (const auto& item : evidence) require(item->releases.load() == 1,"property_cleanup_wrong");
}
void alternate_build_paths(std::shared_ptr<const OriginalMapResources> map, std::array<OriginalResearchChoice,7> choices) {
    for (const auto scenario : {Scenario::miracle,Scenario::skill_limit}) {
        auto evidence = std::make_shared<Evidence>();
        Running running([&] { return direct_callbacks(make_plan(std::make_shared<Fixture>(map,choices,evidence,scenario))); });
        const Client client(running.service.bound_port()); start(client); buy_land(client);
        build(client,scenario == Scenario::miracle ? 13 : 11);
        if (scenario == Scenario::miracle) {
            require(evidence->kind.load() == 13 && evidence->level.load() == 1 && evidence->license_count.load() == 0,
                "property_miracle_license_not_consumed");
        } else {
            require(evidence->stage.load() == static_cast<int>(OriginalPropertyStage::research),"property_skill_limit_waited_for_upgrade");
            client.send(message(Bytes{57,0,2,0,0xff,0x81}));
            require(client.plain() == Bytes{0x3f,0x40,0x56,0x34,0xff} && client.plain() == turn,"property_skill_limit_research_exit_stalled");
        }
        client.send(message(Bytes{10,0})); client.closed(); running.finish();
        require(evidence->releases.load() == 1,"property_alternate_cleanup_wrong");
    }
}
}
int main() {
    try {
        const Network network;
        constexpr std::u8string_view source = RICHONLINE_LEGACY_RESOURCE_ROOT;
        const auto root = std::filesystem::path(std::u8string(source.begin(),source.end()));
        const auto map = std::make_shared<OriginalMapResources>(original_map_resources(load_original_emp(root/"Map"/"BS_1_1.emp"),10));
        const auto road = std::find_if(map->roads.begin(),map->roads.end(),[](const auto& cell) { return cell.tile == 119; });
        require(road != map->roads.end() && road->property_id == 104,"property_original_map_oracle_wrong");
        const auto property = std::find_if(map->properties.begin(),map->properties.end(),[](const auto& record) { return record.id == 104; });
        require(property != map->properties.end() && property->owner == -1,"property_original_initial_owner_wrong");
        const auto choices = load_original_research_resources(root/"Data"/"BwbValue.kpd").choices;
        require(choices[0] == OriginalResearchChoice{1044,1},"property_original_research_oracle_wrong");
        research_and_isolation(map,choices,static_cast<std::uint32_t>(property->price));
        alternate_build_paths(map,choices);
        std::cout << "PASS original property encrypted TCP purchase, construction, research, inventory and isolated rejection.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
