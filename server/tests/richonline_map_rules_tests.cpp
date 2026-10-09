#include "richonline_map_package.hpp"
#include "richonline_chance_events.hpp"
#include "original_options.hpp"

#include <fstream>
#include <algorithm>
#include <iostream>
#include <nlohmann/json.hpp>
#include <queue>
#include <set>

namespace {
using namespace richnet;
void check(bool value,std::string_view reason) { if(!value) throw std::runtime_error(std::string(reason)); }
template<class F> void rejects(F action,std::string_view code) {
    try { action(); } catch(const CodecError& error) { check(error.what()==code,error.what()); return; }
    throw std::runtime_error("expected_map_rules_rejection");
}
std::string effect(RichonlineMapStaticEffect value) {
    switch(value) {
    case RichonlineMapStaticEffect::none: return "none";
    case RichonlineMapStaticEffect::tickets: return "local_tickets";
    case RichonlineMapStaticEffect::card_reward: return "server_card_reward";
    case RichonlineMapStaticEffect::pending_server_reward: return "pending_server_reward";
    case RichonlineMapStaticEffect::chance_event: return "server_chance_event";
    case RichonlineMapStaticEffect::shop: return "server_shop_close_or_actions";
    case RichonlineMapStaticEffect::paired_portal: return "local_paired_portal";
    case RichonlineMapStaticEffect::local_vendor: return "local_vendor57";
    case RichonlineMapStaticEffect::unsupported: return "unsupported";
    }
    throw std::runtime_error("invalid_static_effect_enum");
}
void classification() {
    RichonlineRoadCell road{7,1,37,42,true,{}};
    auto rule=richonline_map_static_rule(road);
    check(rule.effect==RichonlineMapStaticEffect::none && rule.has_property_phase &&
        !rule.human_waits_for_server && !rule.synthetic_waits_for_server,"chapter3_property_phase_wrong");
    road.static_type=44;
    check(richonline_map_static_rule(road).has_property_phase,"chapter2_property_phase_wrong");
    road.property_ref=-1;
    for(const auto pending_type:std::array<std::int8_t,4>{51,52,53,54}) {
        road.static_type=pending_type;
        rule=richonline_map_static_rule(road);
        check(rule.effect==RichonlineMapStaticEffect::pending_server_reward && rule.human_waits_for_server &&
            !rule.synthetic_waits_for_server,"pending_reward_synthetic_or_human_wait_wrong");
    }
    road.static_type=8;
    check(richonline_map_static_rule(road).effect==RichonlineMapStaticEffect::card_reward,
        "card8_classification_changed");
    road.static_type=58; rule=richonline_map_static_rule(road);
    check(rule.effect==RichonlineMapStaticEffect::chance_event && rule.human_waits_for_server &&
        rule.synthetic_waits_for_server,"event58_synthetic_wait_lost");
    road.static_type=28; rule=richonline_map_static_rule(road);
    check(rule.effect==RichonlineMapStaticEffect::paired_portal && !rule.human_waits_for_server,
        "portal28_created_nonexistent_ACK");
    road.static_type=57;
    check(richonline_map_static_rule(road).effect==RichonlineMapStaticEffect::local_vendor,"vendor57_treated_as_empty");
    road.static_type=2;
    check(richonline_map_static_rule(road).effect==RichonlineMapStaticEffect::unsupported,"unknown_rule_pretended_closed");
}
void tail_boundaries(const std::filesystem::path& root,const RichonlineMapPackage& package,
    const RichonlineMapRuleResources& resources) {
    const auto source=load_original_emp(root/"Map"/package.map_name);
    const auto base=load_original_price_base(root/"Data"/"Option.kpd");
    const auto parse=[&](const OriginalEmp& emp) {
        return richonline_map_rule_resources(resources.stage,emp,package.resource_rules,base);
    };
    const auto write=[](OriginalEmp& emp,std::size_t offset,std::uint32_t value) {
        for(std::size_t i=0;i<4;++i)
            emp.payload.at(emp.tail_offset+offset+i)=static_cast<std::uint8_t>((value>>(8U*i))&0xffU);
    };
    auto bad=source;
    bad.payload.resize(bad.tail_offset+119U);
    rejects([&] { parse(bad); },"richonline_map_rules_tail_truncated");
    bad=source; write(bad,120,0xffffffffU);
    rejects([&] { parse(bad); },"richonline_map_rules_tail_array_invalid");
    const auto card_offset=124U+4U*resources.source_dword_array.size();
    bad=source; write(bad,card_offset+4U+8U,static_cast<std::uint32_t>(resources.card_weights.front().card));
    rejects([&] { parse(bad); },"richonline_map_rules_card_array_invalid");
    bad=source; write(bad,card_offset+8U,0xffffffffU);
    rejects([&] { parse(bad); },"richonline_map_rules_card_array_invalid");
    const auto pool_offset=card_offset+4U+8U*resources.card_weights.size();
    bad=source; write(bad,pool_offset+4U,32767);
    rejects([&] { parse(bad); },"richonline_map_rules_card_pool_invalid");
    const auto extra_offset=pool_offset+8U+4U*(resources.pool_a_ids.size()+resources.pool_b_ids.size());
    bad=source; write(bad,extra_offset,0x7fffffffU);
    rejects([&] { parse(bad); },"richonline_map_rules_tail_array_invalid");
    bad=source; bad.payload.resize(bad.payload.size()-1U);
    rejects([&] { parse(bad); },"richonline_map_rules_tail_truncated");
    check(resources.initial_npcs.empty(),"BS_1_1_fixture_gained_resource_npcs");
    bad=source; write(bad,resources.parsed_tail_bytes-4U,1);
    bad.payload.resize(bad.payload.size()+8U);
    write(bad,resources.parsed_tail_bytes,115); write(bad,resources.parsed_tail_bytes+4U,0x89abcdefU);
    const auto npc=parse(bad).initial_npcs;
    check(npc.size()==1 && npc[0].position==115 && npc[0].type==29 && npc[0].owner==-1 &&
        npc[0].lifetime==-1 && npc[0].unconsumed_source_value==0x89abcdefU,
        "NEW_resource_npc_fields_or_unconsumed_bits_lost");
    write(bad,resources.parsed_tail_bytes,0xffffffffU);
    rejects([&] { parse(bad); },"richonline_map_rules_initial_npcs_invalid");
    auto stage=resources.stage; stage.signature[0]^=0x80U;
    rejects([&] { richonline_map_rule_resources(stage,source,package.resource_rules,base); },
        "richonline_map_rules_stage_metadata_mismatch");
}
void bs22_routes_and_policy_boundaries(const std::filesystem::path& root,const RichonlineMapRuleResources& resources) {
    std::set<std::int16_t> outer{83};
    std::queue<std::int16_t> queue; queue.push(83);
    while(!queue.empty()) {
        const auto position=queue.front(); queue.pop();
        for(const auto next:resources.topology.cell(position).neighbors)
            if(next && outer.insert(*next).second) queue.push(*next);
    }
    check(outer.size()==43 && !outer.contains(150),"BS_2_2_component_geometry_changed");
    const std::array<std::vector<std::int16_t>,2> six_steps{{
        {82,98,114,130,146,162},{232,231,230,229,228,227}}};
    for(std::size_t index=0;index<2;++index) {
        const auto spawn=resources.conservative_spawns->at(index);
        for(std::int32_t budget=1;budget<=18;++budget)
            for(const bool last:{false,true}) {
                const auto route=build_richonline_route(resources.topology,
                    {spawn.position,spawn.direction,budget,std::nullopt,true,false},
                    [last](std::size_t size) { return last ? size-1U : 0U; });
                check(route.landings.size()==static_cast<std::size_t>(budget),"BS_2_2_route_budget_unconsumed");
                for(const auto position:route.landings)
                    check(outer.contains(position),"BS_2_2_route_escaped_selected_component");
                if(budget==6 && !last)
                    check(route.landings==six_steps[index],"BS_2_2_selected_first_six_steps_changed");
            }
    }
    const auto geometry=[&](std::initializer_list<std::size_t> roads) {
        auto emp=load_original_emp(root/"Map"/"BS_2_2.emp");
        for(std::size_t position=0;position<resources.topology.cells().size();++position)
            emp.payload.at(emp.terrain_offset+position*64U)=0xffU;
        for(const auto position:roads) emp.payload.at(emp.terrain_offset+position*64U)=8;
        return richonline_road_topology(emp);
    };
    const auto tie=geometry({34,35,36,37,66,67,68,69});
    check(choose_richonline_map_spawns(tie,RichonlineMapSpawnPolicy::largest_adjacent_component)==
        std::array<RichonlineMapSpawnChoice,2>{{{35,1},{36,1}}},"spawn_component_tie_break_changed");
    const auto lacking=geometry({34,35,51,52,82,83,84});
    rejects([&] { choose_richonline_map_spawns(lacking,RichonlineMapSpawnPolicy::largest_adjacent_component); },
        "richonline_map_rules_spawn_candidates_missing");
}
nlohmann::json run(const std::filesystem::path& root) {
    const auto table=RichonlineChanceEventTable::load(root);
    nlohmann::json audit={{"scope","NEW 13 shipped BossWar map resource rules"},
        {"spawn_policy","package-selected native road graph policy; BS_2_2 selects its largest adjacent component; not recovered historical constants"},
        {"maps",nlohmann::json::array()}};
    struct ExpectedSpawn { std::string_view map; std::int16_t human,boss; std::uint8_t human_direction,boss_direction; };
    constexpr std::array expected_spawns{
        ExpectedSpawn{"BS_1_1.emp",115,236,1,1}, ExpectedSpawn{"BS_1_2.emp",99,220,1,0},
        ExpectedSpawn{"BS_1_3.emp",85,233,1,1}, ExpectedSpawn{"BS_1_4.emp",84,235,1,1},
        ExpectedSpawn{"BS_2_1.emp",82,203,1,0}, ExpectedSpawn{"BS_2_2.emp",83,233,1,1},
        ExpectedSpawn{"BS_2_3.emp",83,234,1,1}, ExpectedSpawn{"BS_2_4.emp",86,231,1,1},
        ExpectedSpawn{"BS_3_1.emp",99,124,1,1}, ExpectedSpawn{"BS_3_2.emp",118,233,1,1},
        ExpectedSpawn{"BS_3_3.emp",114,172,0,0}, ExpectedSpawn{"BS_3_4.emp",84,91,1,1},
        ExpectedSpawn{"V_BS_1_1.emp",99,106,1,1}};
    for(const auto* package:richonline_map_packages()) {
        const auto resources=load_richonline_map_rule_resources(root,*package,package->special_category ? 2U : 0U);
        const auto emp=load_original_emp(root/"Map"/package->map_name);
        check(resources.parsed_tail_bytes==emp.payload.size()-emp.tail_offset,"shipped_tail_boundary_unparsed");
        const auto& stage=resources.stage;
        check(stage.map_name==package->map_name && resources.properties.width==stage.width &&
            resources.properties.height==stage.height,"rule_resources_cross_map_binding");
        const bool enabled=package->map_name=="BS_1_1.emp" || package->map_name=="BS_1_2.emp" ||
            package->map_name=="BS_1_4.emp" || package->map_name=="V_BS_1_1.emp";
        check(package->runtime_enabled==enabled,"runtime_gate_widened_without_integration");
        const auto expected=std::find_if(expected_spawns.begin(),expected_spawns.end(),[&](const auto& item) {
            return item.map==package->map_name;
        });
        check(expected!=expected_spawns.end(),"map_missing_expected_spawn_policy");
        const auto expected_policy=package->map_name=="BS_2_2.emp" ?
            RichonlineMapSpawnPolicy::largest_adjacent_component : RichonlineMapSpawnPolicy::all_candidates_connected;
        check(package->resource_rules.spawn_policy==expected_policy,"unexpected_map_spawn_policy");
        check(resources.conservative_spawns==std::array<RichonlineMapSpawnChoice,2>{{
            {expected->human,expected->human_direction},{expected->boss,expected->boss_direction}}},
            "map_spawn_pair_or_direction_changed");
        nlohmann::json row={{"map",package->map_name},{"map_id",stage.map_id},{"category",stage.category},
            {"mode",stage.mode},{"dimensions",{stage.width,stage.height}},{"signature",stage.signature},
            {"runtime_enabled",package->runtime_enabled},{"role",stage.boss.role},{"mood",stage.boss.mood},
            {"equipment",stage.boss.equipment},{"base_cash",stage.boss.base_cash},{"dice",stage.boss.max_dice},
            {"boss_count",stage.boss.count},{"monetary_scale",stage.monetary_scale},{"wait_seconds",stage.wait_seconds},
            {"game_months",stage.game_months},{"player_selection",stage.player_selection},
            {"player_count_choices",stage.player_count_choices},{"default_building_kind",stage.default_building_kind},
            {"human_funds",{stage.human.cash,stage.human.deposit,stage.human.tickets}},
            {"spawn_policy",expected_policy==RichonlineMapSpawnPolicy::largest_adjacent_component ?
                "largest_adjacent_component" : "all_candidates_connected"},
            {"scenario_caps",stage.scenario_caps},{"boss_skills",stage.boss.building_skills},
            {"pawn_gold",stage.pawn_gold},{"first_reward",{stage.first_reward.experience,stage.first_reward.gold,stage.first_reward.item_count}},
            {"invest_base",stage.invest_base ? nlohmann::json(*stage.invest_base) : nlohmann::json(nullptr)},
            {"invest_return",stage.invest_return ? nlohmann::json(*stage.invest_return) : nlohmann::json(nullptr)},
            {"first_items",stage.first_reward.item_ids},{"repeat_reward",{stage.repeat_reward.experience,stage.repeat_reward.gold,stage.repeat_reward.item_count}},
            {"repeat_items",stage.repeat_reward.item_ids},{"static_types",nlohmann::json::object()},
            {"terrain_types",nlohmann::json::object()},{"static_rules",nlohmann::json::array()},
            {"property_road_types",nlohmann::json::array()},{"prebuilt",nlohmann::json::array()},
            {"initial_npcs",nlohmann::json::array()},{"card_weights",nlohmann::json::array()},
            {"chance_categories",nlohmann::json::object()},{"source_prelude_words",resources.source_prelude},
            {"source_postlude_words",resources.source_postlude},{"source_dword_array",resources.source_dword_array},
            {"source_extra_arrays",resources.source_extra_arrays},
            {"parsed_tail_bytes",resources.parsed_tail_bytes},{"pool_a",resources.pool_a_ids},{"pool_b",resources.pool_b_ids},
            {"package_policies",{{"chance",package->closed_chance.has_value()},{"npc",package->closed_npcs.has_value()},
                {"combat",package->combat.has_value()},{"opening",package->opening_hand.has_value()}}}};
        std::set<std::int8_t> property_types;
        for(const auto& cell:resources.topology.cells()) {
            if(!cell.walkable) continue;
            const auto rule=richonline_map_static_rule(cell);
            check(rule.effect!=RichonlineMapStaticEffect::unsupported,"shipped_map_unclassified_static_type");
            if(rule.has_property_phase) property_types.insert(cell.static_type);
        }
        for(const auto type:property_types) row["property_road_types"].push_back(type);
        for(const auto& [type,count]:resources.static_counts) {
            row["static_types"][std::to_string(type)]=count;
            const auto rule=richonline_map_static_rule(RichonlineRoadCell{0,1,type,-1,true,{}});
            row["static_rules"].push_back({{"type",type},{"effect",effect(rule.effect)},
                {"human_waits",rule.human_waits_for_server},{"boss_waits",rule.synthetic_waits_for_server}});
        }
        for(const auto& [type,count]:resources.terrain_counts) row["terrain_types"][std::to_string(type)]=count;
        for(const auto& property:resources.properties.properties) if(property.level>0)
            row["prebuilt"].push_back({{"id",property.id},{"sprite",property.sprite_type},{"kind",property.kind},{"level",property.level},
                {"price",property.price},{"owner",property.owner ? nlohmann::json(*property.owner) : nlohmann::json(nullptr)},
                {"district",property.district},{"roads",property.road_tiles},{"resource_record",property.resource_record}});
        for(const auto& npc:resources.initial_npcs) row["initial_npcs"].push_back({{"position",npc.position},
            {"type",npc.type},{"owner",npc.owner},{"lifetime",npc.lifetime},{"unconsumed_source_value",npc.unconsumed_source_value}});
        for(const auto& card:resources.card_weights) row["card_weights"].push_back({{"id",card.card},{"weight",card.weight}});
        for(std::size_t i=0;i<resources.portals.size();++i)
            row["portal_pairs"][std::to_string(i==0 ? 28 : 61)]=resources.portals[i] ?
                nlohmann::json(*resources.portals[i]) : nlohmann::json(nullptr);
        row["conservative_spawn_error"]=resources.conservative_spawn_error ?
            nlohmann::json(*resources.conservative_spawn_error) : nlohmann::json(nullptr);
        row["conservative_spawns"]=nlohmann::json(nullptr);
        if(resources.conservative_spawns) {
            row["conservative_spawns"]=nlohmann::json::array();
            for(const auto& spawn:*resources.conservative_spawns)
                row["conservative_spawns"].push_back({{"position",spawn.position},{"direction",spawn.direction}});
        }
        row["chance_event_count"]=table.size(package->map_name);
        for(std::size_t i=0;i<table.size(package->map_name);++i) {
            const auto& event=table.event(package->map_name,static_cast<std::int32_t>(i));
            const auto key=std::to_string(event.category);
            if(!row["chance_categories"].contains(key)) row["chance_categories"][key]=0;
            row["chance_categories"][key]=row["chance_categories"][key].get<unsigned>()+1U;
        }
        audit["maps"].push_back(std::move(row));
    }
    const auto& first=find_richonline_map_package("BS_1_1.emp",0);
    const auto bs=load_richonline_map_rule_resources(root,first,0);
    check(bs.conservative_spawns==std::array<RichonlineMapSpawnChoice,2>{{{115,1},{236,1}}},"BS_1_1_spawn_policy_changed");
    check(bs.source_extra_arrays[0]==std::vector<std::uint32_t>{1038,1044,1044,1046} &&
        bs.source_extra_arrays[1]==std::vector<std::uint32_t>{0,1,3,2,9,4,21,7,17},
        "NEW_tail_source_arrays_skipped_or_deduplicated");
    tail_boundaries(root,first,bs);
    const auto& divided=find_richonline_map_package("BS_2_2.emp",0);
    const auto bs22=load_richonline_map_rule_resources(root,divided,0);
    check(bs22.conservative_spawns==std::array<RichonlineMapSpawnChoice,2>{{{83,1},{233,1}}} &&
        !bs22.conservative_spawn_error,"BS_2_2_largest_component_policy_wrong");
    rejects([&] { choose_richonline_map_conservative_spawns(bs22.topology); },
        "richonline_map_rules_spawn_graph_disconnected");
    rejects([&] { choose_richonline_map_spawns(bs22.topology,static_cast<RichonlineMapSpawnPolicy>(99)); },
        "richonline_map_rules_spawn_policy_invalid");
    bs22_routes_and_policy_boundaries(root,bs22);
    const auto& special=find_richonline_map_package("V_BS_1_1.emp",2);
    const auto zhao=load_richonline_map_rule_resources(root,special,2);
    check(zhao.conservative_spawns==std::array<RichonlineMapSpawnChoice,2>{{{99,1},{106,1}}} &&
        zhao.portals[1]==std::array<std::int16_t,2>{105,229},"Zhao_spawn_or_portal_source_wrong");
    auto bad_portal=load_original_emp(root/"Map"/special.map_name);
    bad_portal.payload.at(bad_portal.tail_offset+80U)=0xffU;
    rejects([&] { richonline_map_rule_resources(zhao.stage,bad_portal,special.resource_rules,
        load_original_price_base(root/"Data"/"Option.kpd")); },"richonline_route_portal_position_invalid");
    auto types=first.resource_rules.expected_static_types; types.push_back(99);
    const RichonlineMapPackage invalid{first.id,first.map_name,first.special_category,first.chance_event,first.reward_card,
        first.readiness,first.runtime_enabled,first.load_stage,first.configure,first.closed_chance,first.closed_npcs,
        first.combat,first.opening_hand,{std::move(types)}};
    rejects([&] { load_richonline_map_rule_resources(root,invalid,0); },"richonline_map_rules_static_boundary_mismatch");
    return audit;
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2 || argc==3,"NEW_resource_root_required"); classification(); const auto audit=run(argv[1]);
        if(argc==3) { std::ofstream output(argv[2],std::ios::binary); check(static_cast<bool>(output),"audit_output_failed"); output<<audit.dump(2); }
        std::cout<<"PASS NEW 13-map independent resource rules, effect classification and spawn/portal boundaries\n";
    } catch(const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
