#include "richonline_combat_bridge.hpp"
#include "richonline_boss_stage.hpp"
#include "richonline_combat_resources.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* why) { if(!value) throw std::runtime_error(why); }
void rejects(auto action,const char* why) {
    try { action(); } catch(const CodecError& error) { check(std::string(error.what())==why,error.what());return; }
    throw std::runtime_error("missing_bridge_rejection");
}
struct Fixture {
    std::shared_ptr<RichonlineGameLedger> ledger=std::make_shared<RichonlineGameLedger>(
        std::vector<RichonlineGameFunds>{{10000,1000,100,{}},{100000,1000,100,{}}});
    std::shared_ptr<RichonlineBossCards> cards;
    std::shared_ptr<RichonlineBossProperty> property;
    std::shared_ptr<RichonlineGroundObjects> ground;
    RichonlineCombatWorld world;
    std::array<RichonlineActorStatus,2> statuses{};
    std::array<bool,2> active{true,true};
    std::array<RichonlineCombatActorRef,2> refs;
    explicit Fixture(const std::filesystem::path& root):refs{{{0,232,&statuses[0],{true,false,false,false,true},&active[0]},
        {1,231,&statuses[1],{true,false,false,false,true},&active[1]}}} {
        const auto stage=load_richonline_boss_stage(root,"BS_1_1.emp");
        cards=std::make_shared<RichonlineBossCards>(std::make_shared<const RichonlineChanceResources>(
            RichonlineChanceResources::load(root)),7,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0,0}});
        property=std::make_shared<RichonlineBossProperty>(root,7,ledger,stage);
        const auto topology=load_richonline_road_topology(root/"Map"/"BS_1_1.emp");
        std::vector<std::int16_t> roads;
        for(const auto& cell:topology.cells()) if(cell.walkable) roads.push_back(cell.position);
        ground=std::make_shared<RichonlineGroundObjects>(std::move(roads));
        world.width=static_cast<std::uint16_t>(topology.width());world.height=static_cast<std::uint16_t>(topology.height());
        world.resources={3000,4000,5000,1000,1500,3,2,1,2,2};
        world.step=[width=world.width,height=world.height](std::int16_t position,std::uint8_t direction)->std::optional<std::int16_t> {
            const auto x=position%width,y=position/width;
            if(direction==0 && x>0) return static_cast<std::int16_t>(position-1);
            if(direction==1 && x+1<width) return static_cast<std::int16_t>(position+1);
            if(direction==2 && y>0) return static_cast<std::int16_t>(position-width);
            if(direction==3 && y+1<height) return static_cast<std::int16_t>(position+width);
            return {};
        };
        world.targets=[](std::uint8_t,RichonlineCombatEffect,const RichonlineCombatSessionView&) {
            return std::vector<std::int16_t>{232};
        };
        world.card_targets=world.targets;
        world.resolve_terms=[](const RichonlineCombatActorView&,const RichonlineCombatSessionView&) {
            return RichonlineCombatWorld::ResolvedTerms{{},{},0,0};
        };
        world.building=[property=property](const RichonlineCombatBuildingView& before,RichonlineBossBlastBuildingEffect effect) {
            return property->combat_building_effect(before,effect);
        };
    }
    RichonlineCombatBridge bridge(RichonlineBossCombatPolicy policy={}) {
        return {7,ledger,cards,ground,property,world,std::move(policy)};
    }
};
RichonlineBossAttackRandomness random(std::array<std::uint8_t,4> rolls) {
    return {rolls,[](std::size_t) { return std::size_t{0}; }};
}
void shares_ground_funds_inventory_and_clock(const std::filesystem::path& root) {
    Fixture f(root);auto bridge=f.bridge();const auto inventory=f.cards->inventory();
    const auto attack=bridge.boss_turn(f.refs,1,random({80,0,0,0}));
    check(attack.packets.size()==1 && f.ground->snapshot().objects.at(232)==RichonlineGroundObject{12,1,3},
        "shared_ground_owner_lifetime");
    check(f.cards->inventory()==inventory && f.ledger->snapshot(0).funds.cash==10000,"boss_attack_consumed_hand");
    bridge.finish_round(f.refs,1);check(f.ground->snapshot().objects.at(232).byte8==2,"day_one");
    bridge.finish_round(f.refs,2);check(f.ground->snapshot().objects.at(232).byte8==1,"red_day");
    const auto same=f.ground->snapshot();
    check(bridge.finish_round(f.refs,2).packets.empty() && f.ground->snapshot()==same,"day_duplicate");
    const auto expired=bridge.finish_round(f.refs,3);
    check(expired.packets.size()==2 && f.ground->snapshot().objects.empty() &&
        f.ledger->snapshot(0).funds.cash==7000 && f.ledger->snapshot(1).funds.cash==97000,"expiry_not_committed_to_shared_ledger");
    f.ground->place(232,{12,1,3});
    const auto step=bridge.stepped_mine(f.refs,232);
    check(step.packets.empty() && f.ground->snapshot().objects.empty() &&
        f.ledger->snapshot(0).funds.cash==4000,"step_duplicated_animation_or_damage");
    f.ground->place(232,{27,1,3});
    bridge.finish_round(f.refs,4);
    check(f.ground->snapshot().objects.at(232)==RichonlineGroundObject{27,1,2},"supermine_kind_day_preserved");
    bridge.finish_round(f.refs,5);
    check(f.ground->snapshot().objects.at(232)==RichonlineGroundObject{27,1,1},"supermine_kind_red_preserved");
    const auto super=bridge.finish_round(f.refs,6);
    check(super.packets.size()==2 && f.ground->snapshot().objects.empty() &&
        f.ledger->snapshot(0).funds.cash==0 && *f.ledger->snapshot(0).funds.deposit==0 &&
        !f.active[0] && f.ledger->snapshot(1).funds.cash==89000,"supermine_shared_damage_expiry_terminal");
}
void stale_planning_and_property_atomicity(const std::filesystem::path& root) {
    Fixture f(root);
    const RichonlineLandingContext landing{1,232,33,216,3,true,2,false};
    f.property->land(landing);f.property->land(landing);
    check(f.property->building(216)->level==1,"property_setup");
    auto bridge=f.bridge({{RichonlineCombatEffect::nuclear}});
    bridge.boss_turn(f.refs,1,random({90,0,0,0}));
    check(f.property->building(216)->level==0 && f.property->building(216)->kind==-1 && f.property->owner(216)==1,
        "nuclear_did_not_commit_shared_property");
    const auto before=f.ledger->snapshot(0);
    f.world.targets=[&](std::uint8_t,RichonlineCombatEffect,const RichonlineCombatSessionView&) {
        f.statuses[0].sleepwalking=1;return std::vector<std::int16_t>{232};
    };
    auto stale=f.bridge();
    rejects([&] { stale.boss_turn(f.refs,1,random({90,0,0,0})); },"richonline_combat_bridge_stale");
    check(f.ledger->snapshot(0)==before && f.ground->snapshot().objects.empty(),"stale_plan_mutated_shared_stores");
    f.statuses[0].sleepwalking=0;
    f.ledger->adjust(0,before,{-static_cast<std::int64_t>(before.funds.cash)+500,-1000,0,0});
    const auto death=bridge.boss_turn(f.refs,1,random({90,0,0,0}));
    check(death.bankrupt_actors==std::vector<std::uint8_t>{0} && !f.active[0] &&
        f.ledger->snapshot(0).funds.cash==0,"bankruptcy_not_forwarded_to_authority");
}
void ground_prepare_is_allocation_before_commit() {
    RichonlineGroundObjects ground({0,1});
    const auto before=ground.snapshot();
    auto prepared=ground.prepare(before,{{0,{12,1,3}}});
    check(ground.snapshot()==before && ground.matches(prepared),"ground_prepare_not_pure");
    check(ground.commit_prepared(prepared) && !ground.commit_prepared(prepared) &&
        ground.snapshot().objects.at(0)==RichonlineGroundObject{12,1,3},"ground_prepared_not_one_use");
    const auto next=ground.snapshot();auto stale=ground.prepare(next,{});
    ground.place(1,{0,255,255});
    const auto current=ground.snapshot();
    check(!ground.matches(stale) && !ground.commit_prepared(stale) && ground.snapshot()==current,
        "stale_ground_prepared_mutation");
    rejects([&] { ground.prepare(current,{{2,{12,1,3}}}); },"richonline_ground_position_invalid");
}
void human_cards_commit_shared_inventory_once(const std::filesystem::path& root) {
    Fixture f(root);auto bridge=f.bridge();
    RichonlineChanceInventory hand{};hand[3]={1044,1};hand[5]={1046,2};f.cards->commit_inventory(hand);
    const auto mine=bridge.human_card(f.refs,{RichonlineTargetCard::mine1044,7,3,0,232},7);
    hand[3]={};
    check(mine.packets==std::vector<Bytes>{{0xbd,0x40,7,0,3,0,232,0}} && f.cards->inventory()==hand &&
        f.ground->snapshot().objects.at(232)==RichonlineGroundObject{12,0,3},"human_mine_shared_inventory_ground");
    rejects([&] { bridge.human_card(f.refs,{RichonlineTargetCard::mine1044,7,3,0,232},7); },"richonline_combat_human_card_not_owned");
    const auto funds=f.ledger->snapshot(0);const auto ground=f.ground->snapshot();
    rejects([&] { bridge.human_card(f.refs,{RichonlineTargetCard::missile1046,8,5,0,232},7); },
        "richonline_combat_human_card_calendar_mismatch");
    check(f.cards->inventory()==hand && f.ledger->snapshot(0)==funds && f.ground->snapshot()==ground,
        "invalid_human_card_partial_commit");
    const auto missile=bridge.human_card(f.refs,{RichonlineTargetCard::missile1046,7,5,0,232},7);
    hand[5].count=1;
    check(missile.packets==std::vector<Bytes>{{0xbf,0x40,7,0,5,0,232,0,0,0}} && f.cards->inventory()==hand &&
        f.ground->snapshot().objects.empty() && f.ledger->snapshot(0).funds.cash==6000,"human_missile_chain_once");
    f.statuses[0].sleepwalking=1;
    rejects([&] { bridge.human_card(f.refs,{RichonlineTargetCard::missile1046,7,5,0,232},7); },
        "richonline_combat_human_card_actor_controlled");
    check(f.cards->inventory()==hand,"controlled_human_card_consumed");
}
void human_nuclear_uses_shared_property_and_safe_exclusion(const std::filesystem::path& root) {
    Fixture f(root);auto bridge=f.bridge();
    const RichonlineLandingContext landing{1,232,33,216,3,true,2,false};
    f.property->land(landing);f.property->land(landing);
    RichonlineChanceInventory hand{};hand[6]={1063,1};hand[7]={1075,1};f.cards->commit_inventory(hand);
    const auto nuke=bridge.human_card(f.refs,{RichonlineTargetCard::nuclear1063,7,6,0,232},7);
    hand[6]={};
    check(nuke.packets==std::vector<Bytes>{{0xcc,0x40,7,0,6,0,232,0,0,0}} && f.cards->inventory()==hand &&
        f.property->building(216)->level==0 && f.property->building(216)->kind==-1 && f.property->owner(216)==1 &&
        f.ledger->snapshot(0).funds.cash==8500,"human_nuclear_property_inventory_damage");
    const auto safe=bridge.human_card(f.refs,{RichonlineTargetCard::safe_nuclear1075,7,7,0,232},7);
    hand[7]={};
    check(safe.packets==std::vector<Bytes>{{0xd5,0x40,7,0,7,0,232,0,0,0}} && f.cards->inventory()==hand &&
        f.ledger->snapshot(0).funds.cash==8500 && f.ledger->snapshot(1).funds.cash==96900,"human_safe_nuclear_self_exclusion");
}
void helmet_status_and_inventory_commit_together(const std::filesystem::path& root) {
    Fixture f(root);RichonlineChanceInventory hand{};hand[3]={1076,3};f.cards->commit_inventory(hand);
    const auto limits=RichonlinePropUseLimits::parse("[PROP]\nprop=1076\nrule=BS\nnum=2\n");
    f.world.helmet=[limits](const RichonlineCombatActorView& actor,const RichonlineCombatSessionView&) {
        return prepare_richonline_safety_helmet(actor.inventory,actor.status.safety_helmet_uses,3,limits,true);
    };
    const auto initial=f.ledger->snapshot(0);
    f.world.targets=[&](std::uint8_t,RichonlineCombatEffect,const RichonlineCombatSessionView&) {
        f.statuses[0].stay=1;return std::vector<std::int16_t>{232};
    };
    auto stale=f.bridge();
    rejects([&] { stale.boss_turn(f.refs,1,random({90,0,0,0})); },"richonline_combat_bridge_stale");
    check(f.cards->inventory()==hand && f.statuses[0].safety_helmet_uses==0 && f.ledger->snapshot(0)==initial,
        "stale_activation_consumed_shared_helmet_or_counter");
    f.statuses[0].stay=0;
    f.world.targets=[](std::uint8_t,RichonlineCombatEffect,const RichonlineCombatSessionView&) {
        return std::vector<std::int16_t>{232};
    };
    auto bridge=f.bridge();const auto attacks=bridge.boss_turn(f.refs,1,random({90,90,90,90}));
    check(attacks.packets.size()==4 && f.cards->inventory()[3].count==1 && f.statuses[0].safety_helmet_uses==2 &&
        f.ledger->snapshot(0).funds.cash==8000,"helmet_counter_inventory_damage_not_shared_atomic_authority");
    f.ground->place(232,{12,1,3});bridge.stepped_mine(f.refs,232);
    check(f.cards->inventory()[3].count==1 && f.statuses[0].safety_helmet_uses==2 &&
        f.ledger->snapshot(0).funds.cash==5000,"mine_bridge_activated_projectile_helmet");
}
void fire_uses_shared_terms_and_atomic_survival(const std::filesystem::path& root) {
    Fixture f(root);f.ground->place(232,{26,1,3});
    f.statuses[1].possession=3;f.statuses[0].possession=0;
    f.refs[0].capabilities.mine_immune_vehicle=true;
    f.world.resolve_terms=[](const RichonlineCombatActorView& actor,const RichonlineCombatSessionView&) {
        RichonlineCombatWorld::ResolvedTerms terms{{},{},0,0};
        if(actor.slot==1){terms.attack.equipment_percentage=20;terms.flat_attack=100;}
        else {terms.defense.equipment_percentage=10;terms.flat_defense=50;}
        return terms;
    };
    f.world.helmet=[](const auto&,const auto&)->std::optional<RichonlineBossCards::PreparedConsumption> {
        throw CodecError("fire_must_not_invoke_projectile_helmet");
    };
    auto bridge=f.bridge();const auto hand=f.cards->inventory();const auto ground=f.ground->snapshot();
    const auto initial=f.ledger->snapshot(0);unsigned preflight=0;
    rejects([&]{bridge.fire_landing(f.refs,0,232,2000,[]{throw CodecError("fire_continuation_rejected");});},
        "fire_continuation_rejected");
    check(f.ledger->snapshot(0)==initial && f.cards->inventory()==hand && f.ground->snapshot()==ground,
        "fire_preflight_partially_committed");
    const auto hit=bridge.fire_landing(f.refs,0,232,2000,[&]{++preflight;});
    // 2000 *1.5 *1.2 *0.5 *0.9 +100 -50 =1670.
    check(hit.packets.empty() && hit.bankrupt_actors.empty() && preflight==1 &&
        f.ledger->snapshot(0).funds.cash==8330 && f.ground->snapshot()==ground && f.cards->inventory()==hand,
        "fire_modifiers_or_persistent_ground_wrong");
    auto poor=f.ledger->snapshot(0);auto funds=poor.funds;funds.cash=670;funds.deposit=1000;
    f.ledger->commit(0,poor,funds);
    const auto lethal=bridge.fire_landing(f.refs,0,232,2000,[]{throw CodecError("fatal_fire_called_continuation");});
    check(lethal.packets.empty() && lethal.bankrupt_actors==std::vector<std::uint8_t>{0} && !f.active[0] &&
        f.ledger->snapshot(0).funds.cash==0 && *f.ledger->snapshot(0).funds.deposit==0 &&
        f.ground->snapshot()==ground,"fire_exact_total_bankruptcy_wrong");
    for(const auto owner:std::array<std::uint8_t,3>{0,1,255}) {
        Fixture neutral(root);neutral.ground->place(232,{26,owner,3});neutral.statuses[1].possession=3;
        if(owner==1){neutral.active[1]=false;neutral.refs[1].capabilities.active=false;}
        auto b=neutral.bridge();b.fire_landing(neutral.refs,0,232,2000,[]{});
        check(neutral.ledger->snapshot(0).funds.cash==8000,"fire_self_neutral_or_inactive_owner_damage_wrong");
    }
    Fixture stale(root);stale.ground->place(232,{26,1,3});auto b=stale.bridge();const auto before=stale.ledger->snapshot(0);
    rejects([&]{b.fire_landing(stale.refs,0,232,2000,[&]{stale.statuses[0].stay=1;});},"richonline_combat_bridge_stale");
    check(stale.ledger->snapshot(0)==before,"fire_stale_status_debited");
}
void poison_shared_count_relations_and_stale_commit(const std::filesystem::path& root) {
    Fixture f(root);RichonlineChanceInventory hand{};hand[2]={1182,6};f.cards->commit_inventory(hand);
    std::array<RichonlineRawActorState,8> raw{};for(auto& r:raw)r={-1,-1,-1,-1,true};
    std::array<std::array<std::uint8_t,8>,2> relations{};relations[0][1]=3;relations[1][0]=2;
    std::uint32_t count=0;
    const RichonlineResearchCardRequest request{RichonlineResearchCard::poison1182,9,2,0,{},1,0xa5};
    const RichonlineResearchCardContext context{7,9,0,0,true,true};
    const std::array<RichonlinePoisonCell,1> footprint{{{231,0}}};
    f.world.resolve_terms=[&](const auto&,const auto&){f.statuses[0].stay=1;return RichonlineCombatWorld::ResolvedTerms{{},{},0,0};};
    auto stale=f.bridge();const auto funds=f.ledger->snapshot(1);
    rejects([&]{stale.poison_card(f.refs,request,context,count,{3,2500},footprint,raw,relations);},"richonline_combat_bridge_stale");
    check(count==0 && f.cards->inventory()==hand && f.ledger->snapshot(1)==funds && relations[0][1]==3 && relations[1][0]==2,
        "poison_partial_count_or_relations_on_stale");
    f.statuses[0].stay=0;f.world.resolve_terms=[](const auto&,const auto&){return RichonlineCombatWorld::ResolvedTerms{{},{},0,0};};
    auto bridge=f.bridge();
    for(std::uint32_t use=0;use<4;++use) {
        const auto before=f.ledger->snapshot(1).funds.cash;
        const auto result=bridge.poison_card(f.refs,request,context,count,{3,2500},footprint,raw,relations);
        check(result.packets.size()==1 && count==use+1 && f.ledger->snapshot(1).funds.cash==before-(use==3?3750U:2500U),
            "poison_count_or_strength_not_committed");
    }
    check(relations[0][1]==0 && relations[1][0]==0 && f.cards->inventory()[2].count==2,"poison_relations_inventory_commit");
    auto invalid=request;invalid.slot=1;const auto before=f.ledger->snapshot(1);
    rejects([&]{bridge.poison_card(f.refs,invalid,context,count,{3,2500},footprint,raw,relations);},"richonline_research_card_not_owned");
    check(count==4 && f.ledger->snapshot(1)==before && f.cards->inventory()[2].count==2,"poison_refusal_raised_count");
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_path_required");shares_ground_funds_inventory_and_clock(argv[1]);
        stale_planning_and_property_atomicity(argv[1]);
        ground_prepare_is_allocation_before_commit();
        human_cards_commit_shared_inventory_once(argv[1]);
        human_nuclear_uses_shared_property_and_safe_exclusion(argv[1]);
        helmet_status_and_inventory_commit_together(argv[1]);
        fire_uses_shared_terms_and_atomic_survival(argv[1]);
        poison_shared_count_relations_and_stale_commit(argv[1]);
        std::cout<<"PASS NEW shared combat bridge CAS and continuation effects\n";
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n';return 1; }
}
