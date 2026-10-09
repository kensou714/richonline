#include "richonline_combat.hpp"
#include <iostream>
#include <limits>
#include <fstream>
#include <iterator>

namespace {
using namespace richnet;
void check(bool value,const char* why) { if (!value) throw std::runtime_error(why); }
template<class F> void rejects(F f,const char* expected) {
    try { f(); } catch(const CodecError& e) { check(std::string(e.what())==expected,e.what()); return; }
    throw std::runtime_error("missing_combat_rejection");
}
void mine_lifecycle() {
    auto state=plan_richonline_mine_placement({},42,1,true);
    check(state.mines[0].remaining_days==3 && !state.mines[0].red(),"new_mine_days");
    rejects([&]{plan_richonline_mine_placement(state,42,1,true);},"richonline_combat_mine_duplicate");
    rejects([&]{plan_richonline_mine_day(state,1,0x1234,false);},"richonline_combat_day_requires_round_anchor");
    const auto first=plan_richonline_mine_day(state,1,0x1234,true);
    check(state.mines[0].remaining_days==3 && first.expected==state,"planner_mutated_source");
    check(first.packets==std::vector<Bytes>{{0x1e,0x40,0x34,0x12}} && first.after.mines[0].remaining_days==2,"first_day_wire");
    auto duplicate=plan_richonline_mine_day(first.after,1,0x1234,true);
    check(duplicate.packets.empty() && duplicate.after==first.after,"duplicate_day_decremented");
    const auto second=plan_richonline_mine_day(first.after,2,0x1234,true);
    check(second.after.mines[0].red() && second.expired.empty(),"red_day_missing");
    const auto third=plan_richonline_mine_day(second.after,3,0x1234,true);
    check(third.after.mines.empty() && third.expired.size()==1 && third.expired[0].owner==1,"expired_owner_lost");
    check(third.packets==std::vector<Bytes>{{0x1e,0x40,0x34,0x12},{0x17,0x40,0x34,0x12,42,0}},"expiry_order");
    rejects([&]{plan_richonline_mine_day(third.after,2,1,true);},"richonline_combat_stale_day");
    rejects([&]{plan_richonline_mine_day(third.after,5,1,true);},"richonline_combat_day_gap");
    check(!plan_richonline_mine_explosion_wire(1,42,RichonlineExplosionTrigger::stepped_on),"step_double_blast");
    check(!plan_richonline_mine_explosion_wire(1,42,RichonlineExplosionTrigger::missile_chain),"chain_double_blast");
}
void damage_and_bankruptcy() {
    const RichonlineGameFundsSnapshot before{{100,200,88,9},7};
    RichonlineActorStatus attacker,defender;
    const RichonlineCombatDamageTerms terms{250,0,0,true,true};
    const auto plan=plan_richonline_combat_damage(1,before,RichonlineCombatEffect::mine,attacker,defender,
        terms,RichonlineClientDamageApplication::already_applied,{});
    check(plan.expected==before && plan.after==RichonlineGameFunds{0,50,88,9} && !plan.bankrupt && plan.damage==250,"cash_bank_order");
    auto lethal=terms; lethal.resource_base_damage=300;
    const auto dead=plan_richonline_combat_damage(1,before,RichonlineCombatEffect::timed_bomb,attacker,defender,
        lethal,RichonlineClientDamageApplication::already_applied,{});
    check(dead.bankrupt && dead.after.cash==0 && *dead.after.deposit==0,"exact_total_not_fatal");
    attacker.attack_turns=2; attacker.attack_multiplier=1.5F;
    defender.damage_turns=2; defender.damage_multiplier=0.5F;
    const auto scaled=plan_richonline_combat_damage(1,before,RichonlineCombatEffect::missile,attacker,defender,
        {200,10,5,true,true},RichonlineClientDamageApplication::by_queued_attack,{});
    check(scaled.damage==155 && scaled.after==RichonlineGameFunds{0,145,88,9},"status_damage");
    const auto minimum=plan_richonline_combat_damage(1,before,RichonlineCombatEffect::mine,{}, {},
        {1,0,999,true,true},RichonlineClientDamageApplication::already_applied,{});
    check(minimum.damage==1,"minimum_damage");
    RichonlineChanceInventory helmet_before,helmet_after;
    helmet_before[2]={1076,1};
    const RichonlineBossCards::PreparedConsumption helmet{helmet_before,helmet_after,2,1076};
    const auto shield=plan_richonline_combat_damage(1,before,RichonlineCombatEffect::missile,{}, {},terms,
        RichonlineClientDamageApplication::by_queued_attack,helmet);
    check(shield.damage==0 && shield.after==before.funds && shield.safety_helmet_consumption &&
        shield.safety_helmet_consumption->source_inventory==helmet_before,"helmet_not_preserved");
    rejects([&]{plan_richonline_combat_damage(1,before,RichonlineCombatEffect::mine,{}, {},terms,
        RichonlineClientDamageApplication::already_applied,helmet);},"richonline_combat_helmet_effect_invalid");
    auto forged=helmet; forged.remaining_inventory=helmet_before;
    rejects([&]{plan_richonline_combat_damage(1,before,RichonlineCombatEffect::missile,{}, {},terms,
        RichonlineClientDamageApplication::by_queued_attack,forged);},"richonline_combat_helmet_plan_invalid");
    auto unknown=before; unknown.funds.deposit.reset();
    rejects([&]{plan_richonline_combat_damage(1,unknown,RichonlineCombatEffect::mine,{}, {},terms,
        RichonlineClientDamageApplication::already_applied,{});},"richonline_combat_deposit_unknown");
    check(plan_richonline_combat_damage(1,before,RichonlineCombatEffect::nuclear,{}, {},terms,
        RichonlineClientDamageApplication::by_queued_attack,{}).damage==250,"nuclear_shared_damage");
    check(richonline_regular_mine_chain_damage(3000,2)==6300,"chain_bonus");
    check(richonline_mixed_mine_chain_damage(8000,8000,2,3000,5000)==7000,
        "mixed_chain_uses_global_super_hit_count");
    check(richonline_mixed_mine_chain_damage(11000,8000,2,3000,5000)==9625,
        "mixed_chain_preserves_owner_adjustment_ratio");
    check(richonline_mixed_mine_chain_damage(8000,8000,3,3000,5000)==8000,
        "mixed_chain_signed_regular_count_nonpositive");
    check(richonline_mixed_mine_chain_damage(9000,6000,0,3000,5000)==9450,
        "normal_only_chain_uses_adjusted_to_raw_ratio");
    rejects([&] { richonline_mixed_mine_chain_damage(0,8000,0,3000,5000); },
        "richonline_combat_chain_invalid");
    rejects([&] { richonline_mixed_mine_chain_damage(1,1,2147483647U,1,2147483647U); },
        "richonline_combat_chain_overflow");
}
void boss_packet_and_control() {
    const auto missile=encode_richonline_boss_noninventory_attack(0x1234,RichonlineCombatEffect::missile,2,42,{},true);
    check(missile==Bytes{0xbf,0x40,0x34,0x12,0,0xff,42,0,2,0},"boss_actor_bank_fields");
    check(encode_richonline_boss_noninventory_attack(1,RichonlineCombatEffect::mine,1,42,{},true)==
        Bytes{0xbd,0x40,1,0,0,0xff,42,0},"boss_mine_fields");
    check(encode_richonline_boss_noninventory_attack(1,RichonlineCombatEffect::nuclear,7,42,{},true)==
        Bytes{0xcc,0x40,1,0,0,0xff,42,0,7,0},"boss_nuclear_fields");
    check(encode_richonline_boss_noninventory_attack(1,RichonlineCombatEffect::safe_nuclear,1,42,{},true)==
        Bytes{0xd5,0x40,1,0,0,0xff,42,0,1,0},"boss_safe_nuclear_fields");
    RichonlineActorStatus sleep; sleep.sleepwalking=1;
    rejects([&]{encode_richonline_boss_noninventory_attack(1,RichonlineCombatEffect::missile,1,42,sleep,true);},
        "richonline_combat_actor_controlled");
    sleep.sleepwalking=0; sleep.frozen=1;
    check(!richonline_combat_action_allowed(sleep),"frozen_can_attack");
    rejects([&]{encode_richonline_boss_noninventory_attack(1,RichonlineCombatEffect::mine,1,42,{},false);},
        "richonline_combat_target_out_of_view");
}
void resources_modifiers_and_chain() {
    const auto resources=RichonlineCombatResources::parse(
        "[PROP]\nindx=1046\nhurt=1000\n[PROP]\nindx=1063\nhurt=1500\n[PROP]\nindx=1075\nhurt=9999\n",
        "[NPC]\nindx=12\nhurt=3000\n[NPC]\nindx=13\nhurt=4000\n[NPC]\nindx=27\nhurt=5000\n",
        "[ITEM]\nindx=19\nvalue=3\n[ITEM]\nindx=20\nvalue=1\n[ITEM]\nindx=21\nvalue=1\n[ITEM]\nindx=22\nvalue=2\n[ITEM]\nindx=23\nvalue=2\n");
    check(resources.base_damage(RichonlineCombatEffect::safe_nuclear)==1500 && resources.mine_days==3,"resource_source_wrong");
    const auto square=richonline_attack_footprint(RichonlineCombatEffect::nuclear,0,5,5,resources);
    check(square==std::vector<std::int16_t>{0,1,2,5,6,7,10,11,12},"nuclear_edge_clipping");
    check(!richonline_attack_hits_actor(RichonlineCombatEffect::safe_nuclear,1,1,true,false,false,false) &&
        richonline_attack_hits_actor(RichonlineCombatEffect::nuclear,1,1,true,false,false,false),"safe_nuclear_hits_self");
    check(richonline_attack_hits_actor(RichonlineCombatEffect::missile,7,6,true,false,false,false),"eight_actor_slots_rejected");
    check(richonline_boss_blast_building_effect(RichonlineCombatEffect::missile,1,5,true,false)==
        RichonlineBossBlastBuildingEffect::none,"old_mode_building_rule_leaked");
    check(richonline_boss_blast_building_effect(RichonlineCombatEffect::nuclear,1,5,true,false)==
        RichonlineBossBlastBuildingEffect::lower_one_level,"boss_nuclear_wrong_levels");
    RichonlineActorStatus attack,defend; attack.possession=3;defend.possession=0;
    RichonlineCombatModifiers attack_mod,defend_mod;
    attack_mod.possession_amplification=0.1F;defend_mod.possession_amplification=0.1F;
    attack_mod.equipment_percentage=25;defend_mod.equipment_percentage=20;
    check(calculate_richonline_combat_damage(1000,attack,defend,attack_mod,defend_mod,true,100,40)==700,"modifier_order");
    check(calculate_richonline_combat_damage(1000,attack,defend,attack_mod,defend_mod,false,100,40)==280,"boss_exempt_attack_terms");
    std::vector<RichonlineMine> mines{{1,0,3},{2,1,1},{4,2,2}};
    const auto step=[](std::int16_t position,std::uint8_t direction)->std::optional<std::int16_t> {
        if (direction==0 && position<4) return static_cast<std::int16_t>(position+1);
        if (direction==2 && position>0) return static_cast<std::int16_t>(position-1);
        return {};
    };
    const auto chain=plan_richonline_mine_chain(1,mines,1,step);
    check(chain.detonated_mines==std::vector<std::int16_t>{1,2} && chain.blasts.size()==2,"chain_crossed_gap");
    check(chain.blasts[0].mine.owner==0 && chain.blasts[1].mine.owner==1 &&
        chain.blasts[1].positions==std::vector<std::int16_t>{2,3,1},"chain_owner_or_overlap_lost");
    check(mines.size()==3 && chain.affected_positions==std::vector<std::int16_t>{1,2,0,3},"chain_mutates_or_misses");
}
}
int main(int argc,char** argv) {
    try { mine_lifecycle(); damage_and_bankruptcy(); boss_packet_and_control(); resources_modifiers_and_chain();
        if (argc==4) {
            const auto read=[](const char* path) {
                std::ifstream input(path,std::ios::binary);
                if(!input) throw std::runtime_error("resource_read_failed");
                return std::string{std::istreambuf_iterator<char>{input},std::istreambuf_iterator<char>{}};
            };
            const auto actual=RichonlineCombatResources::parse(read(argv[1]),read(argv[2]),read(argv[3]));
            check(actual.mine_damage==3000 && actual.timed_bomb_damage==4000 && actual.missile_damage==1000 &&
                actual.nuclear_damage==1500 && actual.mine_days==3 && actual.mine_range==2 &&
                actual.missile_radius==1 && actual.nuclear_radius==2,"new_resources_unexpected");
        }
        std::cout<<"richonline combat planner tests passed\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
