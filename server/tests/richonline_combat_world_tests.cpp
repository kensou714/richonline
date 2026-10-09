#include "richonline_combat_world.hpp"
#include <algorithm>
#include <cmath>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* why) { if(!value) throw std::runtime_error(why); }
void rejects(auto action,const char* why) {
    try { action(); } catch(const CodecError& error) { check(std::string(error.what())==why,error.what());return; }
    throw std::runtime_error("missing_world_rejection");
}
RichonlineMapCombatPolicy map_policy() {
    return {4,80,10,10,{RichonlineMapProjectile::missile,RichonlineMapProjectile::nuclear,
        RichonlineMapProjectile::safe_nuclear},true,true,true,false};
}
RichonlineCombatWorldPolicy world_policy() {
    return {{"server_manhattan_tile_radius",2,RichonlineProjectileCandidates::all_map_tiles},{},
        [](std::int16_t position,const RichonlineCombatSessionView&) { return position!=231; },{},{},{}};
}
struct Fixture {
    RichonlineBossStage stage;
    RichonlineRoadTopology topology;
    std::shared_ptr<RichonlineBossProperty> property;
    explicit Fixture(const std::filesystem::path& root):stage(load_richonline_boss_stage(root,"BS_1_1.emp")),
        topology(load_richonline_road_topology(root/"Map"/"BS_1_1.emp")),
        property(std::make_shared<RichonlineBossProperty>(root,7,std::array<std::uint32_t,2>{10000,100000},stage)) {}
    RichonlineCombatSessionView state() {
        RichonlineCombatSessionView state;state.game_id=7;state.buildings=property->combat_snapshot().buildings;
        for(std::uint8_t i=0;i<2;++i) {
            RichonlineCombatActorView actor;actor.slot=i;actor.position=static_cast<std::int16_t>(232-i);
            actor.funds={{10000,1000,100,{}},0};state.actors[i]=actor;
        }
        return state;
    }
};
void actual_resources_topology_and_server_targets(const std::filesystem::path& root) {
    Fixture f(root);const auto result=make_richonline_combat_world(root,f.topology,f.stage,{},map_policy(),f.property,world_policy());
    check(result.target_policy=="server_manhattan_tile_radius" && result.boss.projectiles.size()==3,"map_policy_mapping");
    const auto& resources=result.world.resources;
    check(resources.mine_damage==3000 && resources.timed_bomb_damage==4000 && resources.super_mine_damage==15000 &&
        resources.missile_damage==1000 && resources.nuclear_damage==1500 && resources.mine_days==3 &&
        resources.mine_range==2 && resources.missile_radius==1 && resources.nuclear_radius==2,"actual_damage_values");
    auto state=f.state();
    const auto mines=result.world.targets(0,RichonlineCombatEffect::mine,state);
    const auto projectiles=result.world.targets(0,RichonlineCombatEffect::missile,state);
    const auto human_projectiles=result.world.card_targets(0,RichonlineCombatEffect::missile,state);
    check(human_projectiles.size()==f.topology.cells().size() && human_projectiles.size()>projectiles.size(),
        "human_resource_whole_map_not_boss_range");
    check(result.world.card_targets(0,RichonlineCombatEffect::mine,state)==mines,"human_mine_explicit_server_range");
    check(std::ranges::find(mines,232)!=mines.end() && std::ranges::find(mines,231)==mines.end(),
        "mine_self_or_pure_support_filter");
    check(std::ranges::find(projectiles,231)!=projectiles.end() && projectiles.size()>mines.size(),"projectile_all_tiles_policy");
    for(const auto target:projectiles) {
        const auto x1=target%static_cast<std::int32_t>(f.topology.width()),y1=target/static_cast<std::int32_t>(f.topology.width());
        const auto x2=232%static_cast<std::int32_t>(f.topology.width()),y2=232/static_cast<std::int32_t>(f.topology.width());
        check(std::abs(x1-x2)+std::abs(y1-y2)<=2,"target_range_not_enforced");
    }
    for(const auto& cell:f.topology.cells()) for(std::uint8_t direction=0;direction<4;++direction)
        check(result.world.step(cell.position,direction)==(cell.walkable?cell.neighbors[direction]:std::optional<std::int16_t>{}),
            "mine_step_does_not_use_verified_geometry");
    const auto initial=result.capabilities(1,state.actors[1]->status,false);
    check(!initial.active && !initial.in_hospital && !initial.in_prison && !initial.mine_immune_vehicle &&
        initial.attack_modifiers_enabled,"closed_initial_capabilities");
    check(result.world.resolve_terms(*state.actors[0],state).flat_attack==0,"neutral_human_terms");
    state.actors[0]->status.possession=5;
    rejects([&] { result.world.resolve_terms(*state.actors[0],state); },"richonline_combat_world_possession_extension_required");
    state.actors[0]->inventory[0]={1076,1};
    const auto helmet=result.world.helmet(*state.actors[0],state);
    check(helmet && helmet->slot==0 && helmet->remaining_inventory[0].card_id==-1 &&
        state.actors[0]->inventory[0].count==1,"actual_helmet_CARD_map_weight_zero_eligibility");
}
void each_npc_possession_has_exact_combat_terms(const std::filesystem::path& root) {
    Fixture f(root);
    auto policy=world_policy();policy.extra_terms=richonline_unamplified_possession_combat_terms;
    const auto result=make_richonline_combat_world(root,f.topology,f.stage,{},map_policy(),f.property,policy);
    auto state=f.state();
    constexpr std::array<std::int8_t,5> ids{0,1,2,3,7};
    constexpr std::array<std::uint32_t,5> attacks{1000,1000,500,1500,1000};
    constexpr std::array<std::uint32_t,5> defenses{500,1500,1000,1000,1000};
    for(std::size_t i=0;i<ids.size();++i) {
        state.actors[0]->status.possession=ids[i];state.actors[1]->status.possession.reset();
        const auto human=result.world.resolve_terms(*state.actors[0],state);
        const auto boss=result.world.resolve_terms(*state.actors[1],state);
        check(human.attack.possession_amplification==0.0F && human.defense.possession_amplification==0.0F,
            "ordinary_NPC_possession_invented_building_amplification");
        check(calculate_richonline_combat_damage(1000,state.actors[0]->status,state.actors[1]->status,
            human.attack,boss.defense,true,human.flat_attack,boss.flat_defense)==attacks[i],"NPC_possession_attack_factor");
        check(calculate_richonline_combat_damage(1000,state.actors[1]->status,state.actors[0]->status,
            boss.attack,human.defense,true,boss.flat_attack,human.flat_defense)==defenses[i],"NPC_possession_defense_factor");
    }
    state.actors[0]->status.possession=3;state.actors[1]->status.possession=0;
    const auto attack=result.world.resolve_terms(*state.actors[0],state),defense=result.world.resolve_terms(*state.actors[1],state);
    check(calculate_richonline_combat_damage(1000,state.actors[0]->status,state.actors[1]->status,
        attack.attack,defense.defense,true,0,0)==750,"possession_roles_combined_once");
}
void equipment_cash_building_and_extensions(const std::filesystem::path& root) {
    Fixture f(root);f.stage.boss.equipment[6]=234;
    const auto result=make_richonline_combat_world(root,f.topology,f.stage,{},map_policy(),f.property,world_policy());
    auto state=f.state();state.actors[1]->funds.funds.cash=9999;
    auto terms=result.world.resolve_terms(*state.actors[1],state);
    check(terms.flat_attack==25 && terms.attack.equipment_percentage==1 && terms.defense.equipment_percentage==0,
        "stage_equipment_attributes");
    state.actors[1]->funds.funds.cash=10000;
    check(result.world.resolve_terms(*state.actors[1],state).flat_attack==0,"stage_cash_condition_not_dynamic");
    state.actors[0]->defense_building_source=216;state.actors[0]->attack_building_source=217;
    state.buildings={{216,{216},13,1,0,false},{217,{217},14,1,0,false}};
    terms=result.world.resolve_terms(*state.actors[0],state);
    check(std::abs(terms.attack.building_multiplier-1.2F)<0.00001F &&
        std::abs(terms.defense.building_multiplier-0.8F)<0.00001F,"active_building_term_sources");
    state.buildings[0].owner=1;
    rejects([&] { result.world.resolve_terms(*state.actors[0],state); },"richonline_combat_world_active_building_stale");
    std::array<std::uint32_t,32> human{};human[7]=234;
    rejects([&] { make_richonline_combat_world(root,f.topology,f.stage,human,map_policy(),f.property,world_policy()); },
        "richonline_combat_world_human_equipment_extension_required");
    auto policy=world_policy();policy.neutral_human_equipment={234};
    rejects([&] { make_richonline_combat_world(root,f.topology,f.stage,human,map_policy(),f.property,policy); },
        "richonline_combat_world_neutral_equipment_has_attributes");
    policy=world_policy();policy.extra_terms=[](const auto&,const auto&) {
        auto terms=RichonlineCombatWorld::ResolvedTerms{{},{},5,6};terms.attack.possession_amplification=0.1F;return terms;
    };
    policy.capabilities=[](std::uint8_t,const auto&,bool active) { return RichonlineCombatCapabilities{active,false,false,true,true}; };
    const auto extended=make_richonline_combat_world(root,f.topology,f.stage,human,map_policy(),f.property,policy);
    state=f.state();state.actors[0]->funds.funds.cash=9999;
    terms=extended.world.resolve_terms(*state.actors[0],state);
    check(terms.flat_attack==30 && terms.flat_defense==6 && terms.attack.possession_amplification==0.1F &&
        extended.capabilities(0,state.actors[0]->status,true).mine_immune_vehicle,"explicit_extension_terms");
    auto invalid=map_policy();invalid.idle_weight=70;
    rejects([&] { make_richonline_combat_world(root,f.topology,f.stage,{},invalid,f.property,world_policy()); },
        "richonline_combat_world_map_policy_unimplemented");
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_path_required");actual_resources_topology_and_server_targets(argv[1]);
        equipment_cash_building_and_extensions(argv[1]);each_npc_possession_has_exact_combat_terms(argv[1]);
        std::cout<<"PASS NEW combat world actual resources, geometry, targets and capabilities\n";
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n';return 1; }
}
