#include "richonline_boss_property.hpp"
#include "richonline_boss_cards.hpp"
#include "richonline_boss_stage.hpp"
#include <algorithm>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if (!value) throw std::runtime_error(reason); }
RichonlineLandingContext context(bool boss) { return {static_cast<std::uint8_t>(boss ? 1 : 0),232,33,216,3,boss,2,false}; }
void completes_without_rent(RichonlineBossProperty& properties,bool boss) {
    const auto before=properties.cash();
    const auto owner=properties.owner(216);
    const auto building=properties.building(216);
    const auto result=properties.land(context(boss));
    check(result && result->progress==RichonlineLandingProgress::complete && !result->pending_opcode &&
        result->messages==std::vector<Bytes>{{0x13,0x40,0x34,0x12,232,0}},"opponent_property_not_completed_with_only_stop");
    check(properties.cash()==before && properties.owner(216)==owner &&
        properties.building(216)->kind==building->kind && properties.building(216)->level==building->level,
        "boss_mode_opponent_property_invented_rent_or_mutated_building");
    check(!properties.poll(),"opponent_property_left_pending_decision");
}
void player_visits_boss_properties(const std::filesystem::path& root) {
    RichonlineBossProperty properties(root,0x1234,{1,100000},load_richonline_boss_stage(root,"BS_1_1.emp"));
    properties.enable_human_decisions(std::chrono::seconds{5},[]{ return RichonlineBossProperty::Clock::time_point{}; });
    properties.land(context(true));
    completes_without_rent(properties,false);
    for (int level=1;level<=5;++level) {
        properties.land(context(true));
        completes_without_rent(properties,false);
    }
    auto occupied=context(false); occupied.occupied_by_other_actor=true;
    check(!properties.land(occupied),"cooccupancy_combat_was_silently_skipped");
}
void boss_visits_licensed_player_buildings(const std::filesystem::path& root) {
    const auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
    for (const std::int8_t kind : {std::int8_t{14},std::int8_t{16}}) {
        auto stage=load_richonline_boss_stage(root,"BS_1_1.emp");
        stage.scenario_caps.at(static_cast<std::size_t>(kind-11))=5;
        const auto construction=RichonlineConstructionResources::load(root,stage);
        RichonlineBossProperty properties(root,0x1234,{20000,1},stage);
        properties.enable_human_decisions(std::chrono::seconds{5},[]{ return RichonlineBossProperty::Clock::time_point{}; });
        auto cards=std::make_shared<RichonlineBossCards>(resources,0x1234,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0,0}});
        RichonlineChanceInventory inventory{};
        inventory[0]={construction.licence_ids.at(static_cast<std::size_t>(kind-11)),1};
        cards->commit_inventory(inventory);
        std::array<std::int8_t,10> skills{}; skills.fill(7);
        properties.configure_construction(skills,cards);
        properties.land(context(false));
        properties.decide(Bytes{0x20,0,7,0,0,0,0,0,1,0,0,0});
        completes_without_rent(properties,true);
        properties.land(context(false));
        properties.decide(Bytes{0x37,0,7,0,static_cast<std::uint8_t>(kind),0xaa});
        check(properties.building(216)->kind==kind,"licensed_build_setup_failed");
        if (kind==16) {
            for (unsigned level=1;level<=5;++level) {
                const auto before=properties.cash();
                if(level<5) completes_without_rent(properties,true);
                else check(!properties.land(context(true)),"temple_summon_was_silently_skipped");
                for (const auto npc : std::array<std::int8_t,5>{0,1,2,3,7}) {
                    auto attached=context(true); attached.actor_status.possession=npc;
                    if(level==1) check(!properties.land(attached) && properties.cash()==before,
                        "temple_without_coordinator_was_silently_skipped");
                }
                properties.enable_temple_possession(10);
                for(const auto npc : std::array<std::int8_t,5>{0,1,2,3,7}) {
                    auto attached=context(true);attached.actor_status.possession=npc;
                    const auto result=properties.land(attached);
                    const bool extend=npc==1 || npc==2 || npc==7;
                    check(result && result->temple_change && result->temple_change->expected==attached.actor_status &&
                        result->temple_change->extend==extend && result->temple_change->maximum==10 &&
                        result->temple_change->days==(extend ? (level<=3 ? 0 : static_cast<int>(level)-3) :
                            (level<=3 ? static_cast<int>(level) : -1)),"temple_resource_duration_wrong");
                    check(properties.cash()==before && !result->pending_opcode && !properties.poll(),
                        "temple_duration_created_payment_or_decision");
                }
                if(level<5) {
                    auto owner=context(false);owner.actor_status.possession=3;
                    properties.land(owner);
                    properties.decide(Bytes{0x38,0,7,0,1,0});
                }
            }
        } else completes_without_rent(properties,true);
    }
}
void own_temple_upgrade_continuations(const std::filesystem::path& root) {
    auto stage=load_richonline_boss_stage(root,"BS_1_1.emp");stage.scenario_caps[5]=5;
    const auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
    const auto construction=RichonlineConstructionResources::load(root,stage);
    RichonlineBossProperty properties(root,0x1234,{20000,1},stage);
    auto now=RichonlineBossProperty::Clock::time_point{};
    properties.enable_human_decisions(std::chrono::seconds{5},[&]{return now;});
    properties.enable_temple_possession(10);
    auto cards=std::make_shared<RichonlineBossCards>(resources,0x1234,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0,0}});
    RichonlineChanceInventory inventory{};inventory[0]={construction.licence_ids[5],1};cards->commit_inventory(inventory);
    std::array<std::int8_t,10> skills{};skills.fill(7);properties.configure_construction(skills,cards);
    properties.land(context(false));properties.decide(Bytes{0x20,0,7,0,0,0,0,0,1,0,0,0});
    auto owner=context(false);owner.actor_status.possession=3;
    properties.land(owner);
    check(!properties.decide(Bytes{0x37,0,7,0,16,0}).temple_change,"first_construction_ran_temple_phase7");
    for(unsigned level=1;level<=5;++level) {
        skills[5]=static_cast<std::int8_t>(level);properties.configure_construction(skills,cards);
        for(const auto npc : std::array<std::int8_t,5>{0,1,2,3,7}) {
            auto visit=owner;visit.actor_status.possession=npc;
            const auto result=properties.land(visit);const bool extend=npc==0 || npc==3;
            check(result && result->temple_change && result->progress==RichonlineLandingProgress::complete &&
                result->temple_change->extend==extend && result->temple_change->days==
                    (extend ? (level<4 ? 0 : static_cast<int>(level)-3) : (level<4 ? static_cast<int>(level) : -1)),
                "owned_temple_cap_or_controlled_effect_wrong");
        }
        if(level==5) {
            check(!properties.land(context(false)),"owned_temple_summon_silently_skipped");break;
        }
        skills[5]=7;properties.configure_construction(skills,cards);
        if(level==4) {
            const auto before=properties.combat_snapshot();
            check(!properties.land(context(false)) && !properties.poll() &&
                properties.combat_snapshot().buildings==before.buildings,
                "unsupported_upgrade_summon_started_decision_or_mutated_building");
        }
        auto controlled=owner;controlled.actor_status.possession=7;
        const auto skipped=properties.land(controlled);
        check(skipped && skipped->temple_change && !skipped->pending_opcode && properties.building(216)->level==level,
            "controlled_own_temple_effect_was_skipped_or_upgrade_requested");
        const auto pending=properties.land(owner);
        check(pending && pending->pending_opcode==0x38 && !pending->temple_change,"own_temple_effect_ran_before_upgrade");
        const auto cancelled=properties.decide(Bytes{0x38,0,7,0,0,0});
        check(cancelled.temple_change && cancelled.temple_change->days==(level<4 ? 0 : 1) &&
            properties.building(216)->level==level,"cancelled_upgrade_did_not_use_old_level");
        properties.land(owner);now+=std::chrono::seconds{5};
        const auto timed=properties.poll();
        check(timed && timed->temple_change && properties.building(216)->level==level,"timeout_skipped_temple_effect");
        properties.land(owner);
        const auto upgraded=properties.decide(Bytes{0x38,0,7,0,1,0});
        check(upgraded.temple_change && upgraded.temple_change->days==(level+1<4 ? 0 : static_cast<int>(level)-2) &&
            properties.building(216)->level==level+1,"accepted_upgrade_did_not_use_new_level");
    }
}
void prebuilt_temple_without_possession_completes(const std::filesystem::path& root,
    const char* map,std::uint32_t category,std::int16_t position,std::int16_t ref,bool visitor_boss) {
    const auto stage=load_richonline_boss_stage(root,map,category);
    const auto topology=load_richonline_road_topology(root/"Map"/map);
    RichonlineBossProperty properties(root,0x1234,{20000,100000},stage);
    properties.enable_human_decisions(std::chrono::seconds{5},[]{ return RichonlineBossProperty::Clock::time_point{}; });
    const auto& cell=topology.cell(position);
    const auto degree=static_cast<std::uint8_t>(std::count_if(cell.neighbors.begin(),cell.neighbors.end(),
        [](const auto& neighbor){return neighbor.has_value();}));
    check(cell.property_ref==ref && properties.building(ref)->kind==16,"prebuilt_temple_fixture_wrong");
    RichonlineLandingContext owner{static_cast<std::uint8_t>(visitor_boss?0:1),position,cell.static_type,ref,3,!visitor_boss,degree,false};
    if(!properties.owner(ref)) {
        check(properties.land(owner).has_value(),"prebuilt_temple_purchase_missing");
        if(visitor_boss) properties.decide(Bytes{0x20,0,7,0,0,0,0,0,1,0,0,0});
    }
    check(properties.owner(ref)==owner.actor_slot,"prebuilt_temple_owner_wrong");
    auto visitor=owner; visitor.actor_slot=static_cast<std::uint8_t>(visitor_boss?1:0); visitor.synthetic_actor=visitor_boss;
    const auto before=properties.combat_snapshot(); const auto cash=properties.cash();
    check(properties.validate_landing(visitor),"prebuilt_temple_preflight_rejected_no_effect");
    const auto result=properties.land(visitor);
    Bytes expected{0x13,0x40,0x34,0x12}; append_le(expected,static_cast<std::uint16_t>(position),2);
    check(result && result->progress==RichonlineLandingProgress::complete && !result->pending_opcode &&
        result->messages==std::vector<Bytes>{expected},"prebuilt_temple_no_effect_did_not_complete");
    check(properties.cash()==cash && properties.combat_snapshot().buildings==before.buildings && !properties.poll(),
        "prebuilt_temple_no_effect_mutated_state");
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_path_required");
        const std::filesystem::path root(argv[1]);
        player_visits_boss_properties(root);
        boss_visits_licensed_player_buildings(root);
        own_temple_upgrade_continuations(root);
        prebuilt_temple_without_possession_completes(root,"BS_1_3.emp",0,164,149,true);
        prebuilt_temple_without_possession_completes(root,"V_BS_1_1.emp",2,165,198,false);
        std::cout << "PASS NEW BOSS opponent property no-rent phase and unresolved-effect boundaries\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
