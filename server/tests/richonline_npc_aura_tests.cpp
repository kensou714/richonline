#include "richonline_npc_aura.hpp"
#include "original_map.hpp"

#include <cmath>
#include <iostream>
#include <limits>

namespace {
using namespace richnet;
void check(bool value,const char* message) {if(!value) throw std::runtime_error(message);}
template<class F> void rejected(F&& fn,const char* code) {
    try {fn();} catch(const CodecError& error) {check(std::string(error.what())==code,"unexpected_aura_rejection");return;}
    throw std::runtime_error("invalid_aura_accepted");
}
RichonlineRoadTopology geometry() {
    OriginalEmp emp{3,5,5,{}, {},Bytes(8+68*25,0xff),8,8+64*25,0,0};
    return richonline_road_topology(emp);
}
RichonlineRawActorState clear() {return {{},-1,-1,-1,{}};}
RichonlineNpcAuraActor actor(std::uint8_t slot,std::int16_t position,std::uint32_t cash=100,
    std::optional<std::uint32_t> deposit=200) {
    return {slot,position,true,clear(),{{cash,deposit,17,90},0}};
}
RichonlineNpcAuraContext context(std::int8_t npc=4,std::uint8_t source=0,std::uint8_t boss=1) {
    return {3,source,boss,npc,RichonlineNpcAuraEffect{0,1.0F}};
}
std::vector<std::uint8_t> affected(const RichonlineNpcAuraPlan& plan) {
    std::vector<std::uint8_t> result;
    for(const auto& update:plan.updates) result.push_back(update.actor);
    return result;
}
void source_and_geometry() {
    const auto topology=geometry();
    check(!topology.cell(12).walkable,"aura_fixture_requires_nonroad_cells");
    std::array actors{actor(0,12),actor(1,12),actor(2,6),actor(3,18),actor(4,9),actor(5,0),actor(6,12)};
    auto plan=plan_richonline_npc_aura(topology,{30,1},context(),actors);
    check(affected(plan)==std::vector<std::uint8_t>{2,0,6,3},"square_order_or_boss_exclusion_changed");
    for(const auto& update:plan.updates) {
        auto expected=update.before.funds;expected.cash+=30;
        check(update.after==expected,"aura_gain_changed_other_funds");
    }
    check(plan.bankrupt_actors.empty(),"gain_marked_bankruptcy");
    auto boss=context(6,1);
    plan=plan_richonline_npc_aura(topology,{30,0},boss,actors);
    check(affected(plan)==std::vector<std::uint8_t>{0,6},"boss_source_aura_skipped_or_hit_boss");
    check(plan.updates.front().after.cash==70,"aura_tested_target_god_instead_of_source");
    boss.possession.reset();boss.effect.reset();
    check(plan_richonline_npc_aura(topology,{30,1},boss,actors).updates.empty(),"expired_god_still_applied_aura");
    actors[0].position=0;actors[1].position=0;actors[2].position=6;actors[3].position=2;
    actors[4].position=10;actors[5].position=24;actors[6].position=1;
    check(affected(plan_richonline_npc_aura(topology,{30,1},context(),actors))==
        std::vector<std::uint8_t>{0,6,2},"map_corner_square_wrapped");
    check(plan_richonline_npc_aura(topology,{30,std::numeric_limits<std::int32_t>::max()},context(),actors).
        updates.size()==6,"wide_radius_overflowed");
    actors[0].position=24;actors[1].position=24;actors[2].position=18;actors[6].position=23;
    check(affected(plan_richonline_npc_aura(topology,{30,1},context(),actors))==
        std::vector<std::uint8_t>{2,6,0,5},"far_corner_square_clipping_changed");
}
void raw_authority() {
    const auto topology=geometry();
    std::array actors{actor(0,12),actor(1,12),actor(2,12),actor(3,12),actor(4,12),actor(5,12),actor(6,0)};
    actors[0].raw.hotel1493=3;actors[0].raw.movement_reporting552=false;
    actors[1].raw={};actors[2].raw.hospital1494=0;actors[3].raw.jail1495=2;
    actors[4].raw.kidnapped1497=0;actors[5].active=false;actors[5].raw={};actors[6].raw={};
    check(affected(plan_richonline_npc_aura(topology,{30,1},context(),actors))==
        std::vector<std::uint8_t>{0},"aura_raw_status_filters_changed");
    for(auto field:{&RichonlineRawActorState::hospital1494,&RichonlineRawActorState::jail1495,
        &RichonlineRawActorState::kidnapped1497}) {
        actors[0].raw.*field={};
        rejected([&]{plan_richonline_npc_aura(topology,{30,1},context(),actors);},"richonline_npc_aura_target_unknown");
        actors[0].raw.*field=-1;
    }
}
void funds_and_bankruptcy() {
    const auto topology=geometry();
    std::array actors{actor(0,12,100,1000),actor(1,12),actor(2,12,101,0),actor(3,12,30,200),
        actor(4,12,30,20),actor(5,12,0,200)};
    const auto plan=plan_richonline_npc_aura(topology,{100,1},context(6),actors);
    check(plan.bankrupt_actors==std::vector<std::uint8_t>{0,3,4,5},"aura_bankruptcy_cash_gate_changed");
    check(plan.updates[0].after.cash==0 && plan.updates[0].after.deposit==1000,
        "exact_cash_debit_spent_deposit");
    check(plan.updates[1].after.cash==1 && plan.updates[1].after.deposit==0,"positive_cash_marked_insolvent");
    check(plan.updates[2].after.cash==0 && plan.updates[2].after.deposit==130,"deposit_deficit_not_debited");
    check(plan.updates[3].after.cash==0 && plan.updates[3].after.deposit==0,"insufficient_funds_not_clamped");
    check(plan.updates[4].after.deposit==100,"zero_cash_deposit_debit_changed");
    const auto zero=plan_richonline_npc_aura(topology,{0,0},context(6),actors);
    check(zero.bankrupt_actors==std::vector<std::uint8_t>{5},"zero_aura_skipped_cash_bankruptcy");
    actors[0].funds.funds.deposit.reset();
    rejected([&]{plan_richonline_npc_aura(topology,{100,1},context(6),actors);},"richonline_npc_aura_deposit_unknown");
    check(!plan_richonline_npc_aura(topology,{100,0},context(),actors).updates.front().after.deposit,
        "gain_invented_deposit_knowledge");
    actors[0].funds.funds.cash=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    rejected([&]{plan_richonline_npc_aura(topology,{1,0},context(),actors);},"richonline_npc_aura_cash_overflow");
}
void exact_scale_and_validation() {
    const auto topology=geometry();std::array actors{actor(0,12),actor(1,12)};
    auto ctx=context();ctx.effect=RichonlineNpcAuraEffect{1,std::nextafter(4.0F/3.0F,0.0F)};
    check(plan_richonline_npc_aura(topology,{3,0},ctx,actors).amount==3,"x87_product_was_rounded_to_float");
    ctx.effect->multiplier1744=1.0F;
    check(plan_richonline_npc_aura(topology,{16777217,0},ctx,actors).amount==16777216,"x87_base_float_rounding_missing");
    ctx.effect->multiplier1744=0.0F;
    check(plan_richonline_npc_aura(topology,{100,0},ctx,actors).amount==0,"zero_multiplier_changed");
    for(auto value:{-1.0F,std::numeric_limits<float>::infinity(),std::numeric_limits<float>::quiet_NaN()}) {
        ctx.effect->multiplier1744=value;
        rejected([&]{plan_richonline_npc_aura(topology,{3,0},ctx,actors);},"richonline_npc_aura_multiplier_invalid");
    }
    ctx.effect->strength1740=0;
    check(plan_richonline_npc_aura(topology,{3,0},ctx,actors).amount==3,"inactive_multiplier_was_used");
    ctx.effect=RichonlineNpcAuraEffect{1,2.0F};
    rejected([&]{plan_richonline_npc_aura(topology,{std::numeric_limits<std::int32_t>::max(),0},ctx,actors);},
        "richonline_npc_aura_amount_overflow");
    ctx.effect.reset();
    rejected([&]{plan_richonline_npc_aura(topology,{3,0},ctx,actors);},"richonline_npc_aura_effect_unknown");
    ctx=context();ctx.mode=4;
    rejected([&]{plan_richonline_npc_aura(topology,{3,0},ctx,actors);},"richonline_npc_aura_context_invalid");
    ctx=context();
    rejected([&]{plan_richonline_npc_aura(topology,{-1,0},ctx,actors);},"richonline_npc_aura_rules_invalid");
    rejected([&]{plan_richonline_npc_aura(topology,{1,-1},ctx,actors);},"richonline_npc_aura_rules_invalid");
    actors[0].position=25;
    rejected([&]{plan_richonline_npc_aura(topology,{3,0},ctx,actors);},"richonline_npc_aura_position_invalid");
    actors[0].position=12;actors[1].slot=0;
    rejected([&]{plan_richonline_npc_aura(topology,{3,0},ctx,actors);},"richonline_npc_aura_actor_invalid");
    actors[1].slot=1;actors[0].active=false;
    rejected([&]{plan_richonline_npc_aura(topology,{3,0},ctx,actors);},"richonline_npc_aura_source_invalid");
}
void atomic_batch() {
    const auto topology=geometry();
    RichonlineGameLedger ledger({{100,200,17,90},{100,200,17,90},{100,200,17,90}});
    std::array actors{actor(0,12),actor(1,12),actor(2,12)};
    auto plan=plan_richonline_npc_aura(topology,{30,0},context(),actors);
    check(!ledger.commit_batch(plan.updates,[]{return false;}),"rejected_aura_batch_committed");
    check(ledger.snapshot(0)==actors[0].funds && ledger.snapshot(2)==actors[2].funds,"aura_batch_partially_committed");
    bool called=false;
    rejected([&]{ledger.commit_batch(plan.updates,[]()->bool {throw CodecError("aura_commit_callback_failed");});},
        "aura_commit_callback_failed");
    ledger.adjust(2,ledger.snapshot(2),{1,0,0,0});
    rejected([&]{ledger.commit_batch(plan.updates,[&]{called=true;return true;});},"richonline_game_ledger_conflict");
    check(!called && ledger.snapshot(0)==actors[0].funds,"stale_later_actor_mutated_first_actor");
    actors[2].funds=ledger.snapshot(2);plan=plan_richonline_npc_aura(topology,{30,0},context(),actors);
    check(ledger.commit_batch(plan.updates,[]{return true;}),"fresh_aura_batch_rejected");
    check(ledger.snapshot(0).funds.cash==130 && ledger.snapshot(2).funds.cash==131 &&
        ledger.earned_cash(0)==30 && ledger.earned_cash(2)==31,"aura_batch_funds_or_income_changed");
    rejected([&]{ledger.commit_batch(plan.updates,[]{return true;});},"richonline_game_ledger_conflict");
}
}
int main(int argc,char** argv) {
    try {
        if(argc!=2) throw std::runtime_error("NEW_resources_argument_required");
        const auto rules=richnet::RichonlineNpcAuraRules::load(std::filesystem::path(argv[1]));
        check(rules.amount>0 && rules.radius>=0,"NEW_aura_resources_invalid");
        std::cout<<"NEW NPC aura GValue15="<<rules.amount<<" GValue24="<<rules.radius<<'\n';
        source_and_geometry();raw_authority();funds_and_bankruptcy();exact_scale_and_validation();atomic_batch();
        std::cout<<"NPC4/6 aura planner passed\n";return 0;
    } catch(const std::exception& error) {std::cerr<<error.what()<<'\n';return 1;}
}
