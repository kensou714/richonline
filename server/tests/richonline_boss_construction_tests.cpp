#include "richonline_boss_property.hpp"
#include "richonline_boss_cards.hpp"
#include "richonline_boss_stage.hpp"
#include "original_building_resources.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if (!value) throw std::runtime_error(reason); }
RichonlineLandingContext landing(bool boss=false,std::int16_t position=231) {
    return {static_cast<std::uint8_t>(boss ? 1 : 0),position,33,216,3,boss,2,false};
}
Bytes request(std::uint8_t opcode,std::uint8_t choice) { return {opcode,0,7,0,choice,0xa5}; }
Bytes response(std::uint8_t opcode,std::uint8_t choice) { return {opcode,0x40,0x34,0x12,choice}; }
void building(const RichonlineBossProperty& properties,std::int8_t kind,std::uint8_t level) {
    const auto value=properties.building(216);
    check(value && value->kind==kind && value->level==level,"building_state_wrong");
}
template<class Action> void rejects(Action action,const char* reason) {
    try { action(); } catch (const CodecError& error) {
        check(std::string(error.what())==reason,"wrong_decision_rejection"); return;
    }
    throw std::runtime_error("unexpected_decision_accepted");
}
struct Human {
    RichonlineBossProperty::Clock::time_point now{};
    RichonlineBossProperty properties;
    explicit Human(const std::filesystem::path& root,std::int8_t skill=7)
        : properties(root,0x1234,{20000,100000},load_richonline_boss_stage(root,"BS_1_1.emp")) {
        properties.enable_human_decisions(std::chrono::milliseconds{5000},[this] { return now; });
        std::array<std::int8_t,10> skills{}; skills.fill(skill);
        properties.configure_construction(skills);
        const auto offer=properties.land(landing(false,232));
        check(offer && offer->pending_opcode==0x20,"purchase_not_pending");
        properties.decide(Bytes{0x20,0,7,0,0,0,0,0,1,0,0,0});
        check(properties.owner(216)==0 && properties.cash()[0]==19900,"purchase_setup_failed");
    }
    void offer(std::uint16_t opcode,std::int16_t position=231) {
        const auto result=properties.land(landing(false,position));
        check(result && result->progress==RichonlineLandingProgress::await_event && result->pending_opcode==opcode &&
            result->messages==std::vector<Bytes>{{0x13,0x40,0x34,0x12,static_cast<std::uint8_t>(position),0}},
            "owned_property_not_waiting_with_stop");
    }
    void build() {
        offer(0x37);
        const auto result=properties.decide(request(0x37,11));
        check(result.messages==std::vector<Bytes>{response(0x3d,11)},"build_setup_response_wrong");
    }
};
void boss_builds_and_upgrades_shared_property_to_scenario_cap(const std::filesystem::path& root) {
    RichonlineBossProperty properties(root,0x1234,{20000,100000},load_richonline_boss_stage(root,"BS_1_1.emp"));
    properties.land(landing(true,232));
    building(properties,-1,0);
    for (std::uint8_t level=1;level<=5;++level) {
        const auto position=static_cast<std::int16_t>(level%2 ? 231 : 232);
        const auto result=properties.land(landing(true,position));
        check(result && result->progress==RichonlineLandingProgress::complete && result->messages==std::vector<Bytes>{
            {0x13,0x40,0x34,0x12,static_cast<std::uint8_t>(position),0},
            level==1 ? response(0x3d,11) : response(0x3e,1)},"boss_build_or_upgrade_wire_wrong");
        building(properties,11,level);
        check(properties.cash()==std::array<std::uint32_t,2>{20000,99900} && properties.owner(216)==1,
            "boss_build_or_upgrade_changed_cash_or_owner");
    }
    const auto capped=properties.land(landing(true));
    check(capped && capped->progress==RichonlineLandingProgress::complete && capped->messages==std::vector<Bytes>{
        {0x13,0x40,0x34,0x12,231,0}},"max_level_boss_did_not_resume_without_upgrade");
    building(properties,11,5);
}
void human_first_construction_choices_and_duplicates(const std::filesystem::path& root) {
    for (const auto choice : {10,11,255}) {
        Human human(root,0);
        human.offer(0x37);
        building(human.properties,-1,0);
        rejects([&] { human.properties.land(landing()); },"richonline_property_decision_already_pending");
        const auto result=human.properties.decide(request(0x37,static_cast<std::uint8_t>(choice)));
        check(result.progress==RichonlineLandingProgress::complete && result.messages==std::vector<Bytes>{
            response(0x3d,choice==10 ? 10 : 11)},"first_construction_choice_wrong");
        building(human.properties,choice==10 ? -1 : 11,choice==10 ? 0 : 1);
        check(human.properties.cash()==std::array<std::uint32_t,2>{19900,100000} && human.properties.owner(216)==0,
            "first_construction_changed_cash_or_owner");
        rejects([&] { human.properties.decide(request(0x37,11)); },"richonline_property_no_pending_decision");
        check(!human.properties.poll(),"completed_build_remained_pending");
    }
}
void human_upgrade_waits_and_resolves_both_choices(const std::filesystem::path& root) {
    for (const bool accept : {false,true}) {
        Human human(root); human.build(); human.offer(0x38,232);
        building(human.properties,11,1);
        const auto result=human.properties.decide(request(0x38,accept ? 1 : 0));
        check(result.progress==RichonlineLandingProgress::await_event && result.pending_opcode==0x39 && result.messages==std::vector<Bytes>{
            response(0x3e,accept ? 1 : 0)},"upgrade_choice_wrong");
        building(human.properties,11,accept ? 2 : 1);
        check(human.properties.cash()==std::array<std::uint32_t,2>{19900,100000},"upgrade_debited_money");
        rejects([&] { human.properties.decide(request(0x38,1)); },"richonline_research_request_opcode");
        human.properties.decide(request(0x39,0xff));
        rejects([&] { human.properties.decide(request(0x39,0xff)); },"richonline_property_no_pending_decision");
    }
}
void timeouts_and_late_choices_resume_without_mutation(const std::filesystem::path& root) {
    for (const bool upgrade : {false,true}) {
        for (const bool late_click : {false,true}) {
            Human human(root);
            if (upgrade) human.build();
            human.offer(upgrade ? 0x38 : 0x37);
            human.now+=std::chrono::milliseconds{4999};
            check(!human.properties.poll(),"construction_expired_early");
            human.now+=std::chrono::milliseconds{1};
            const auto result=late_click ? std::optional{human.properties.decide(request(upgrade ? 0x38 : 0x37,upgrade ? 1 : 11))} :
                human.properties.poll();
            check(result && result->progress==(upgrade?RichonlineLandingProgress::await_event:RichonlineLandingProgress::complete) && result->messages==std::vector<Bytes>{
                response(upgrade ? 0x3e : 0x3d,upgrade ? 0 : 10)},"construction_timeout_response_wrong");
            building(human.properties,upgrade ? 11 : -1,upgrade ? 1 : 0);
            check(human.properties.cash()[0]==19900 && !human.properties.poll(),"timeout_mutated_cash_or_repeated");
            if(upgrade) {
                human.now+=std::chrono::milliseconds{5000};
                const auto research=human.properties.poll();
                check(research && research->progress==RichonlineLandingProgress::complete &&
                    research->messages==std::vector<Bytes>{response(0x3f,0xff)} && !human.properties.poll(),"research_timeout_did_not_resume");
            }
        }
    }
}
void upgrade_cap_is_minimum_of_human_skill_and_scenario(const std::filesystem::path& root) {
    for (const auto skill : {0,2,7}) {
        Human human(root,static_cast<std::int8_t>(skill)); human.build();
        const auto expected=skill==7 ? 5 : (skill==0 ? 1 : 2);
        for (int level=2;level<=expected;++level) {
            human.offer(0x38);
            human.properties.decide(request(0x38,1));
            human.properties.decide(request(0x39,0xff));
        }
        building(human.properties,11,static_cast<std::uint8_t>(expected));
        const auto capped=human.properties.land(landing(false,232));
        check(capped && capped->progress==RichonlineLandingProgress::await_event && capped->pending_opcode==0x39 && capped->messages.size()==1 &&
            !human.properties.poll(),"human_upgrade_cap_did_not_resume");
        human.properties.decide(request(0x39,0xff));
        rejects([&] { human.properties.decide(request(0x38,1)); },"richonline_property_no_pending_decision");
    }
}
void licensed_choices_consume_once_and_disabled_choices_preserve_inventory(const std::filesystem::path& root) {
    const auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
    for (const auto quantity : {0,1,2}) {
        Human human(root);
        auto cards=std::make_shared<RichonlineBossCards>(resources,0x1234,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0,0}});
        RichonlineChanceInventory inventory{};
        inventory[2]={512,static_cast<std::int16_t>(quantity)};
        inventory[4]={513,1}; inventory[6]={1038,1};
        cards->commit_inventory(inventory);
        std::array<std::int8_t,10> skills{}; skills.fill(7);
        human.properties.configure_construction(skills,cards);
        human.offer(0x37);
        const auto disabled=human.properties.decide(request(0x37,15));
        check(disabled.messages==std::vector<Bytes>{response(0x3d,10)} && cards->inventory()==inventory,
            "disabled_choice_built_or_consumed_licence");
        human.offer(0x37);
        const auto selected=human.properties.decide(request(0x37,14));
        check(selected.messages==std::vector<Bytes>{response(0x3d,quantity>0 ? 14 : 10)},"licence_eligibility_wrong");
        building(human.properties,quantity>0 ? 14 : -1,quantity>0 ? 1 : 0);
        if (quantity>0) inventory[2]=quantity==1 ? RichonlineChanceCardSlot{} : RichonlineChanceCardSlot{512,1};
        check(cards->inventory()==inventory && human.properties.cash()[0]==19900,"licence_consumption_or_money_wrong");
        rejects([&] { human.properties.decide(request(0x37,14)); },"richonline_property_no_pending_decision");
        check(cards->inventory()==inventory,"duplicate_construction_consumed_again");
    }
    Human absent(root); absent.offer(0x37);
    check(absent.properties.decide(request(0x37,14)).messages==std::vector<Bytes>{response(0x3d,10)},
        "missing_inventory_built_licensed_kind");
}
void default_first_build_does_not_use_upgrade_cap(const std::filesystem::path& root) {
    auto stage=load_richonline_boss_stage(root,"BS_1_1.emp");
    stage.scenario_caps[0]=0; stage.boss.building_skills[0]=0;
    RichonlineBossProperty properties(root,0x1234,{20000,100000},stage);
    properties.enable_human_decisions(std::chrono::seconds{5},[]{ return RichonlineBossProperty::Clock::time_point{}; });
    properties.configure_construction({});
    properties.land(landing(false,232));
    properties.decide(Bytes{0x20,0,7,0,0,0,0,0,1,0,0,0});
    properties.land(landing(false));
    const auto built=properties.decide(request(0x37,11));
    check(built.messages==std::vector<Bytes>{response(0x3d,11)},"default_first_build_rejected_by_upgrade_cap");
    building(properties,11,1);
    const auto capped=properties.land(landing(false,232));
    check(capped && capped->progress==RichonlineLandingProgress::await_event && capped->pending_opcode==0x39 && capped->messages.size()==1 && !properties.poll(),
        "default_first_build_exemption_allowed_upgrade");
    properties.decide(request(0x39,0xff));
}
void combat_uses_shared_property_and_rejects_stale_plans(const std::filesystem::path& root) {
    Human human(root); human.build();
    auto& properties=human.properties;
    const auto before=properties.combat_snapshot();
    auto after=before.buildings;
    const auto index=static_cast<std::size_t>(std::find_if(after.begin(),after.end(),[](const auto& entry) {
        return entry.property==216;
    })-after.begin());
    check(index<after.size(),"combat_property_missing");
    const auto width=static_cast<std::int16_t>(load_richonline_road_topology(root/"Map"/"BS_1_1.emp").width());
    check(after[index].owner==0 && after[index].level==1 && after[index].footprint==
        std::vector<std::int16_t>{static_cast<std::int16_t>(215-width),static_cast<std::int16_t>(216-width),215,216},
        "combat_property_snapshot_footprint");
    after[index]=properties.combat_building_effect(after[index],RichonlineBossBlastBuildingEffect::lower_one_level);
    check(after[index].owner==0 && after[index].level==0 && after[index].kind==-1,"combat_zero_level_normalization");
    const auto prepared=properties.prepare_combat(before,after);
    building(properties,11,1);
    const auto money=properties.cash();
    check(properties.commit_combat(prepared) && !properties.commit_combat(prepared),"combat_commit_replay");
    check(properties.cash()==money && properties.owner(216)==0,"combat_unrelated_funds_changed");
    building(properties,-1,0);
    human.build(); building(properties,11,1);
    rejects([&] { properties.prepare_combat(before,after); },"richonline_property_combat_stale");
    const auto fresh=properties.combat_snapshot();
    auto invalid=fresh.buildings; ++invalid[index].level;
    rejects([&] { properties.prepare_combat(fresh,invalid); },"richonline_property_combat_transition_invalid");
    invalid=fresh.buildings; invalid[index].owner=1;
    rejects([&] { properties.prepare_combat(fresh,invalid); },"richonline_property_combat_transition_invalid");
    invalid=fresh.buildings; invalid[index].footprint[0]=0;
    rejects([&] { properties.prepare_combat(fresh,invalid); },"richonline_property_combat_transition_invalid");
    auto unowned=fresh.buildings;
    unowned[index]=properties.combat_building_effect(unowned[index],RichonlineBossBlastBuildingEffect::remove_ownership);
    const auto removal=properties.prepare_combat(fresh,unowned);
    const auto snapshot=properties.combat_snapshot();
    check(properties.validate_landing(landing()),"landing_preflight_supported");
    check(properties.combat_snapshot().buildings==snapshot.buildings &&
        properties.combat_snapshot().revision==snapshot.revision && !properties.poll(),"landing_preflight_mutated");
    human.offer(0x38);
    check(!properties.combat_matches(removal) && !properties.commit_combat(removal),"combat_pending_decision_not_rejected");
    rejects([&] { properties.validate_landing(landing()); },"richonline_property_decision_already_pending");
    properties.decide(request(0x38,0));
    properties.decide(request(0x39,0xff));
    check(properties.commit_combat(removal) && !properties.owner(216),"combat_remove_owner_failed");
    check(properties.cash()==money,"combat_owner_removal_changed_funds");
}
void research_selection_produces_cards_and_cancels_downgraded_jobs(const std::filesystem::path& root) {
    const auto choices=load_original_research_resources(root/"Data/BwbValue.kpd").choices;
    const auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
    Human human(root); human.build();
    auto cards=std::make_shared<RichonlineBossCards>(resources,0x1234,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0,0}});
    human.properties.configure_construction({7,7,7,7,7,7,7,7,7,7},cards);
    human.offer(0x38); auto upgraded=human.properties.decide(request(0x38,1));
    check(upgraded.pending_opcode==0x39,"research_not_pending_after_upgrade");
    rejects([&]{human.properties.decide(request(0x39,3));},"richonline_research_choice_unavailable");
    const auto selected=human.properties.decide(request(0x39,2));
    check(selected.progress==RichonlineLandingProgress::complete && selected.messages==std::vector<Bytes>{response(0x3f,2)} &&
        human.properties.pending_research_jobs()==3,"research_selection_did_not_schedule_three");
    const auto empty=cards->inventory();
    for(int day=0;day<choices[1].days*3;++day) human.properties.advance_research(1);
    check(cards->inventory()==empty && human.properties.pending_research_jobs()==3,"boss_turn_advanced_human_research");
    auto expected=empty;
    for(int cycle=0;cycle<3;++cycle) {
        for(int day=1;day<choices[1].days;++day) human.properties.advance_research(0);
        check(cards->inventory()==expected,"research_produced_early");
        expected=cards->prepare_add(choices[1].card);
        human.properties.advance_research(0);
        check(cards->inventory()==expected && human.properties.pending_research_jobs()==static_cast<std::size_t>(2-cycle),
            "research_inventory_or_combination_diverged");
    }
    check(choices[1].card==1038,"NEW_level2_research_card_changed");
    const auto produced=std::find_if(cards->inventory().begin(),cards->inventory().end(),[](const auto& item){return item.card_id==1038;});
    check(produced!=cards->inventory().end(),"research_card_missing_from_authority");
    const auto use=cards->prepare_use({7,static_cast<std::int8_t>(produced-cards->inventory().begin()),0,4});
    check(use.has_value() && use->die==4,"researched_controlled_die_not_usable");
    human.offer(0x38); human.properties.decide(request(0x38,0)); human.properties.decide(request(0x39,2));
    const auto before=human.properties.combat_snapshot(); auto after=before.buildings;
    for(auto& item:after) if(item.property==216)
        item=human.properties.combat_building_effect(item,RichonlineBossBlastBuildingEffect::lower_one_level);
    check(human.properties.commit_combat(human.properties.prepare_combat(before,after)),"research_downgrade_failed");
    human.properties.advance_research(1);
    check(human.properties.pending_research_jobs()==0 && cards->inventory()==expected,"downgraded_research_not_cancelled");
    human.offer(0x38); human.properties.decide(request(0x38,1));
    human.now+=std::chrono::milliseconds{5000};
    const auto late=human.properties.decide(request(0x39,1));
    check(late.messages==std::vector<Bytes>{response(0x3f,0xff)} && human.properties.pending_research_jobs()==0,
        "late_research_scheduled_after_timeout");
}
void research_full_inventory_and_recipe_apply_once(const std::filesystem::path& root) {
    const auto choices=load_original_research_resources(root/"Data/BwbValue.kpd").choices;
    check(choices[1].card==1038 && choices[1].days==1,"NEW_level2_research_resource_changed");
    const auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::parse(
        "BS_1_1.emp\t5\t0\t0\t0\t0\t0\t1038\timg\ttext\n",
        "[PROP]\nindx=1038\ntype=CARD\nenable=true\n[PROP]\nindx=1044\ntype=CARD\nenable=true\n",
        "[ITEM]\nenable=true\nsrc0=1038,2\ndest=1044\n",{{"BS_1_1.emp",{1038,1044}}}));
    for(const bool full:{false,true}) {
        Human human(root);human.build();
        auto cards=std::make_shared<RichonlineBossCards>(resources,0x1234,RichonlineBossCardPolicy{"BS_1_1.emp",0,1038,{0,0}});
        RichonlineChanceInventory inventory{};
        if(full) inventory.fill({1038,1}); else inventory[0]={1038,5};
        cards->commit_inventory(inventory);
        human.properties.configure_construction({7,7,7,7,7,7,7,7,7,7},cards);
        human.offer(0x38);human.properties.decide(request(0x38,1));human.properties.decide(request(0x39,2));
        human.properties.advance_research(0);
        if(full) check(cards->inventory()==inventory,"full_research_inventory_changed");
        else {
            RichonlineChanceInventory combined{};combined[0]={1044,1};
            check(cards->inventory()==combined,"research_did_not_apply_slot_based_recipe_once");
        }
        check(human.properties.pending_research_jobs()==2,"completed_research_job_not_retired");
        human.properties.advance_research(0);human.properties.advance_research(0);
        const auto completed=cards->inventory();
        human.properties.advance_research(0);
        check(human.properties.pending_research_jobs()==0 && cards->inventory()==completed,"research_reward_replayed");
    }
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_path_required"); const std::filesystem::path root(argv[1]);
        boss_builds_and_upgrades_shared_property_to_scenario_cap(root);
        human_first_construction_choices_and_duplicates(root);
        human_upgrade_waits_and_resolves_both_choices(root);
        timeouts_and_late_choices_resume_without_mutation(root);
        upgrade_cap_is_minimum_of_human_skill_and_scenario(root);
        licensed_choices_consume_once_and_disabled_choices_preserve_inventory(root);
        default_first_build_does_not_use_upgrade_cap(root);
        combat_uses_shared_property_and_rejects_stale_plans(root);
        research_selection_produces_cards_and_cancels_downgraded_jobs(root);
        research_full_inventory_and_recipe_apply_once(root);
        std::cout << "PASS NEW owned property construction, upgrades, licences and timeout decisions\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
