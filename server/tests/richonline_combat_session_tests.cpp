#include "richonline_combat_session.hpp"
#include "richonline_combat_resources.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* why) { if (!value) throw std::runtime_error(why); }
void rejects(auto action,const char* reason) {
    try { action(); }
    catch (const CodecError& error) { check(std::string(error.what())==reason,error.what()); return; }
    throw std::runtime_error("missing_rejection");
}
RichonlineCombatSessionView state() {
    RichonlineCombatSessionView result;
    result.game_id=0x1234;
    for (std::uint8_t i=0;i<3;++i) {
        RichonlineCombatActorView actor;
        actor.slot=i; actor.position=static_cast<std::int16_t>(12+i);
        actor.funds={{10000,1000,80,90},0};
        result.actors[i]=actor;
    }
    return result;
}
RichonlineCombatWorld world() {
    RichonlineCombatWorld result;
    result.width=5; result.height=5;
    result.resources={3000,4000,5000,1000,1500,3,2,1,2,2};
    result.step=[](std::int16_t position,std::uint8_t direction)->std::optional<std::int16_t> {
        const auto x=position%5,y=position/5;
        if (direction==0 && x>0) return static_cast<std::int16_t>(position-1);
        if (direction==1 && x<4) return static_cast<std::int16_t>(position+1);
        if (direction==2 && y>0) return static_cast<std::int16_t>(position-5);
        if (direction==3 && y<4) return static_cast<std::int16_t>(position+5);
        return {};
    };
    result.targets=[](std::uint8_t,RichonlineCombatEffect,const RichonlineCombatSessionView&) {
        return std::vector<std::int16_t>{12};
    };
    return result;
}
RichonlineBossAttackRandomness random(std::array<std::uint8_t,4> rolls) {
    return {rolls,[](std::size_t) { return std::size_t{0}; }};
}
std::uint16_t opcode(const Bytes& wire) { return static_cast<std::uint16_t>(wire[0]|(wire[1]<<8)); }
void attacks() {
    const auto before=state(); auto map=world();
    const auto plan=prepare_richonline_boss_combat_turn(before,map,0,random({0,79,90,99}));
    check(plan.packets.size()==2 && opcode(plan.packets[0])==0x40bf,"projectile_thresholds");
    check(plan.boss_attempts[0].outcome==RichonlineCombatAttemptOutcome::none &&
        plan.boss_attempts[1].outcome==RichonlineCombatAttemptOutcome::none,"none_thresholds");
    check(plan.after.actors[0]->funds.funds.cash==8000 && plan.after.actors[1]->funds.funds.cash==8000 &&
        plan.after.actors[2]->funds.funds.cash==10000,"self_and_footprint_and_accumulation");
    check(plan.funds_updates.size()==2 && plan.after.actors[0]->funds.revision==1 &&
        plan.after.actors[0]->inventory==before.actors[0]->inventory,"coalesced_funds_no_boss_cards");
    check(before.actors[0]->funds.funds.cash==10000 && before.revision==0,"prepare_is_pure");
    check(plan.packets[0][5]==0xff && plan.packets[0][8]==0 && plan.packets[0][9]==0,"actor_card_presentation");
    auto control=before; control.actors[0]->status.sleepwalking=1;
    auto sleep=prepare_richonline_boss_combat_turn(control,map,0,random({80,89,90,99}));
    check(sleep.packets.empty() && sleep.after.revision==0,"sleepwalking_no_attacks");
    for (const auto& attempt:sleep.boss_attempts)
        check(attempt.outcome==RichonlineCombatAttemptOutcome::controlled,"sleepwalking_outcome");
    control.actors[0]->status.sleepwalking=0; control.actors[0]->status.frozen=1;
    check(prepare_richonline_boss_combat_turn(control,map,0,random({99,99,99,99})).packets.empty(),"frozen_no_attacks");
    control.actors[0]->status.frozen=0; control.actors[0]->in_prison=true;
    check(prepare_richonline_boss_combat_turn(control,map,0,random({99,99,99,99})).packets.empty(),"prison_no_attacks");
    auto poor=before; poor.actors[0]->funds.funds.cash=500; poor.actors[0]->funds.funds.deposit=500;
    const auto dead=prepare_richonline_boss_combat_turn(poor,map,0,random({90,90,90,90}));
    check(dead.packets.size()==1 && dead.bankrupt_actors==std::vector<std::uint8_t>{0} &&
        dead.after.actors[0]->funds.funds.cash==0 && dead.after.actors[0]->funds.funds.deposit==0 &&
        dead.boss_attempts[1].outcome==RichonlineCombatAttemptOutcome::actor_eliminated,"boss_self_bankruptcy_stops_attacks");
    check(dead.after.actors[1]->funds.funds.cash==9000,"same_blast_other_victim_still_damaged");
    rejects([&] { prepare_richonline_boss_combat_turn(before,map,0,random({100,0,0,0})); },
        "richonline_combat_session_roll_invalid");
    auto bad_random=random({90,0,0,0}); bad_random.bounded=[](std::size_t bound) { return bound; };
    rejects([&] { prepare_richonline_boss_combat_turn(before,map,0,bad_random); },
        "richonline_combat_session_random_out_of_range");
}
void mines() {
    auto before=state(); auto map=world();
    std::vector<std::size_t> bounds;
    map.targets=[](std::uint8_t,RichonlineCombatEffect,const RichonlineCombatSessionView&) {
        return std::vector<std::int16_t>{12,13};
    };
    auto draws=random({80,89,80,89}); draws.bounded=[&](std::size_t bound) { bounds.push_back(bound); return std::size_t{0}; };
    auto placed=prepare_richonline_boss_combat_turn(before,map,0,draws);
    check(placed.after.mines.mines.size()==2 && placed.after.mines.mines[0].owner==0 &&
        placed.after.mines.mines[0].remaining_days==3 && bounds==std::vector<std::size_t>{2,1},"dynamic_legal_mine_targets");
    check(placed.boss_attempts[2].outcome==RichonlineCombatAttemptOutcome::no_legal_target,"occupied_mine_not_replaced");
    auto day1=prepare_richonline_combat_mine_day(placed.after,map,1,true);
    check(day1.packets.size()==1 && day1.after.mines.mines[0].remaining_days==2 &&
        !day1.after.mines.mines[0].red(),"mine_day_one");
    auto day2=prepare_richonline_combat_mine_day(day1.after,map,2,true);
    check(day2.after.mines.mines[0].red() && day2.after.mines.mines[0].remaining_days==1,"mine_last_day_red");
    const auto duplicate=prepare_richonline_combat_mine_day(day2.after,map,2,true);
    check(duplicate.packets.empty() && duplicate.after.revision==day2.after.revision,"mine_day_idempotent");
    const auto expiry=prepare_richonline_combat_mine_day(day2.after,map,3,true);
    check(expiry.after.mines.mines.empty() && expiry.packets.size()==2 &&
        opcode(expiry.packets[0])==0x401e && opcode(expiry.packets[1])==0x4017,"connected_expiry_one_animation");
    check(expiry.after.actors[0]->funds.funds.cash==3700,"chain_overlap_bonus");
    before.mines.mines={{12,0,1},{13,1,3}};
    before.dynamic_npcs={{14,0}};
    const auto chain=prepare_richonline_combat_mine_day(before,map,1,true);
    check(chain.after.mines.mines.empty() && chain.after.dynamic_npcs.empty() && chain.packets.size()==2,
        "expiry_detonates_fresh_neighbor_and_removes_npc");
    before.actors[0]->status.attack_turns=1; before.actors[0]->status.attack_multiplier=2.0F;
    const auto mixed=prepare_richonline_combat_stepped_mine(before,map,12);
    check(mixed.after.actors[2]->funds.funds.cash==550 && mixed.packets.empty(),
        "owner_modifiers_preserved_per_blast_and_no_step_duplicate");
    before.actors[2]->mine_immune_vehicle=true;
    check(prepare_richonline_combat_stepped_mine(before,map,12).after.actors[2]->funds.funds.cash==10000,
        "vehicle_mine_immunity");
    rejects([&] { prepare_richonline_combat_mine_day(before,map,1,false); },"richonline_combat_day_requires_round_anchor");
    auto stale=day1.after;
    rejects([&] { prepare_richonline_combat_mine_day(stale,map,3,true); },"richonline_combat_day_gap");
    map.targets=[](std::uint8_t,RichonlineCombatEffect,const RichonlineCombatSessionView&) {
        return std::vector<std::int16_t>{12};
    };
    before=state(); before.mines.mines={{12,0,3},{13,1,3}};
    auto missile_chain=prepare_richonline_boss_combat_turn(before,map,0,random({90,0,0,0}));
    check(missile_chain.after.mines.mines.empty() && missile_chain.packets.size()==1 &&
        opcode(missile_chain.packets[0])==0x40bf,"missile_chain_no_duplicate_explosion_wire");
}
void supermines() {
    auto before=state();auto map=world();
    before.actors[2]->position=24;
    before.mines.mines={{12,0,3,RichonlineMineKind::normal},
        {13,1,3,RichonlineMineKind::super}};
    const auto stepped=prepare_richonline_combat_stepped_mine(before,map,12);
    check(stepped.packets.empty() && stepped.after.mines.mines.empty() &&
        stepped.after.actors[0]->funds.funds.cash==3000 &&
        stepped.after.actors[1]->funds.funds.cash==3000 &&
        stepped.after.actors[2]->funds.funds.cash==10000,
        "mixed_chain_global_super_hits_two_victims");
    before.actors[0]->status.attack_turns=1;
    before.actors[0]->status.attack_multiplier=2.0F;
    before.actors[0]->funds.funds={500,500,80,90};
    const auto modified=prepare_richonline_combat_stepped_mine(before,map,12);
    check(modified.bankrupt_actors==std::vector<std::uint8_t>{0} &&
        modified.after.actors[0]->funds.funds.cash==0 &&
        *modified.after.actors[0]->funds.funds.deposit==0 &&
        modified.after.actors[1]->funds.funds.cash==375,
        "mixed_chain_owner_modifier_snapshot_before_bankruptcy");
    before=state();before.mines.mines={{12,0,3,RichonlineMineKind::normal},
        {13,1,3,RichonlineMineKind::super}};
    const auto three=prepare_richonline_combat_stepped_mine(before,map,12);
    check(three.after.actors[0]->funds.funds.cash==2000 &&
        three.after.actors[1]->funds.funds.cash==2000 &&
        three.after.actors[2]->funds.funds.cash==2000,
        "mixed_chain_global_counter_no_regular_branch");
    before=state();before.actors[2]->position=24;
    before.mines.mines={{12,0,1,RichonlineMineKind::super},
        {13,1,3,RichonlineMineKind::normal}};
    const auto expiry=prepare_richonline_combat_mine_day(before,map,1,true);
    check(expiry.packets==std::vector<Bytes>{{0x1e,0x40,0x34,0x12},
        {0x17,0x40,0x34,0x12,12,0}} && expiry.after.mines.mines.empty() &&
        expiry.after.actors[0]->funds.funds.cash==3000,
        "mixed_chain_expiry_one_4017_for_two_mines");
    before.mines.mines={{12,-1,3,RichonlineMineKind::super}};
    before.actors[0]->mine_immune_vehicle=true;
    const auto neutral=prepare_richonline_combat_stepped_mine(before,map,12);
    check(neutral.after.actors[0]->funds.funds.cash==10000 &&
        neutral.after.actors[1]->funds.funds.cash==5000,
        "neutral_supermine_and_vehicle_immunity");
    before.mines.mines[0].kind=static_cast<RichonlineMineKind>(28);
    rejects([&] { prepare_richonline_combat_stepped_mine(before,map,12); },
        "richonline_combat_session_mine_invalid");
}
void helmets_and_buildings() {
    auto before=state(); auto map=world();
    before.actors[1]->inventory[0]={1076,1};
    map.helmet=[](const RichonlineCombatActorView& actor,const RichonlineCombatSessionView&)
        ->std::optional<RichonlineBossCards::PreparedConsumption> {
        return prepare_richonline_safety_helmet(actor.inventory,actor.status.safety_helmet_uses,3,{},true);
    };
    const auto plan=prepare_richonline_boss_combat_turn(before,map,0,random({90,90,0,0}));
    check(plan.card_consumptions.size()==1 && plan.after.actors[1]->inventory[0].card_id==-1 &&
        plan.after.actors[1]->funds.funds.cash==9000 && plan.after.actors[1]->status.safety_helmet_uses==1 &&
        before.actors[1]->status.safety_helmet_uses==0,"helmet_consumed_once_shared_inventory");
    before.buildings={{0,{6,7,11,12},3,2,1,false},{1,{13},10,1,1,true}};
    int effects=0;
    map.building=[&](const RichonlineCombatBuildingView& building,RichonlineBossBlastBuildingEffect effect) {
        ++effects; auto after=building;
        if (effect==RichonlineBossBlastBuildingEffect::remove_ownership) after.owner.reset();
        else if (effect==RichonlineBossBlastBuildingEffect::lower_one_level) {
            --after.level; if (after.level==0) after.kind=0;
        }
        return after;
    };
    const auto blast=prepare_richonline_boss_combat_turn(before,map,0,random({90,0,0,0}),
        {{RichonlineCombatEffect::nuclear}});
    check(effects==2 && blast.after.buildings[0].level==1 && !blast.after.buildings[1].owner,
        "nuclear_normalized_properties_once_and_kind10_clear");
    effects=0;
    const auto missile=prepare_richonline_boss_combat_turn(before,map,0,random({90,0,0,0}));
    check(effects==1 && missile.after.buildings[0].level==2,"missile_no_ordinary_building_downgrade");
    const auto safe=prepare_richonline_boss_combat_turn(before,map,0,random({90,0,0,0}),
        {{RichonlineCombatEffect::safe_nuclear}});
    check(safe.after.actors[0]->funds.funds.cash==10000 && safe.after.actors[2]->funds.funds.cash==8500,
        "safe_nuclear_excludes_self_hits_other_actors");
    map.building={};
    rejects([&] { prepare_richonline_boss_combat_turn(before,map,0,random({90,0,0,0}),
        {{RichonlineCombatEffect::nuclear}}); },"richonline_combat_session_building_adapter_missing");
}
void helmet_limits_exclusions_and_usage_lifetime() {
    auto before=state();auto map=world();
    const auto limits=RichonlinePropUseLimits::parse("[PROP]\nprop=1076\nrule=BS\nnum=2\n");
    map.helmet=[limits](const RichonlineCombatActorView& actor,const RichonlineCombatSessionView&) {
        return prepare_richonline_safety_helmet(actor.inventory,actor.status.safety_helmet_uses,3,limits,true);
    };
    before.actors[1]->inventory[3]={1076,3};
    before.actors[1]->status.sleepwalking=3;
    const auto repeated=prepare_richonline_boss_combat_turn(before,map,0,random({90,90,90,90}));
    check(repeated.card_consumptions.size()==2 && repeated.after.actors[1]->inventory[3].count==1 &&
        repeated.after.actors[1]->status.safety_helmet_uses==2 && repeated.after.actors[1]->funds.funds.cash==8000,
        "helmet_uses_after_earlier_attack_or_sleepwalk_passive_gate");
    check(before.actors[1]->inventory[3].count==3 && before.actors[1]->status.safety_helmet_uses==0,
        "helmet_prepare_changed_authority");
    before.actors[1]->status.frozen=1;
    const auto frozen=prepare_richonline_boss_combat_turn(before,map,0,random({90,0,0,0}));
    check(frozen.after.actors[1]->status.safety_helmet_uses==0 && frozen.after.actors[1]->inventory==before.actors[1]->inventory,
        "excluded_frozen_actor_consumed_helmet");
    before.actors[1]->status.frozen=0;before.actors[0]->inventory[1]={1076,1};
    const auto safe=prepare_richonline_boss_combat_turn(before,map,0,random({90,0,0,0}),{{RichonlineCombatEffect::safe_nuclear}});
    check(safe.after.actors[0]->status.safety_helmet_uses==0 && safe.after.actors[0]->inventory==before.actors[0]->inventory &&
        safe.after.actors[1]->status.safety_helmet_uses==1,"safe_nuclear_self_or_other_helmet_gate");
    before.mines.mines={{12,0,3}};
    const auto mine=prepare_richonline_combat_stepped_mine(before,map,12);
    check(mine.after.actors[1]->status.safety_helmet_uses==0 && mine.after.actors[1]->inventory==before.actors[1]->inventory &&
        mine.after.actors[1]->funds.funds.cash==7000,"mine_consumed_helmet");
    before=state();before.actors[1]->inventory[0]={1076,1};before.actors[1]->status.safety_helmet_uses=65535;
    map.helmet=[](const RichonlineCombatActorView& actor,const RichonlineCombatSessionView&) {
        return prepare_richonline_safety_helmet(actor.inventory,actor.status.safety_helmet_uses,3,{},true);
    };
    const auto wrapped=prepare_richonline_boss_combat_turn(before,map,0,random({90,0,0,0}));
    check(wrapped.after.actors[1]->status.safety_helmet_uses==0 && wrapped.card_consumptions.size()==1,
        "NEW_WORD_usage_increment_does_not_match");
}
void atomic_commit() {
    auto shared=state(); auto map=world();
    RichonlineGameLedger ledger({shared.actors[0]->funds.funds,shared.actors[1]->funds.funds,shared.actors[2]->funds.funds});
    auto plan=prepare_richonline_boss_combat_turn(shared,map,0,random({90,90,0,0}));
    auto stale=prepare_richonline_boss_combat_turn(shared,map,0,random({90,0,0,0}));
    check(!commit_richonline_combat_plan(plan,[](const auto&) { return false; }) && !plan.committed,
        "false_commit_is_retryable");
    rejects([&] { commit_richonline_combat_plan(plan,[](const auto&)->bool { throw CodecError("adapter_failed"); }); },
        "adapter_failed");
    check(!plan.committed && ledger.snapshot(0)==shared.actors[0]->funds,"throw_preserves_uncommitted_state");
    // A production adapter additionally compares shared statuses/cards/map and
    // runs under the session lock. This fixture has no concurrent mutation of
    // those stores; its revision rejects stale whole-session plans.
    const auto adapter=[&](const RichonlineCombatTurnPlan& pending) {
        if (shared.revision!=pending.expected.revision) return false;
        auto prepared=pending.after; // all allocation/validation before commit
        return ledger.commit_batch(pending.funds_updates,[&] {
            using std::swap; swap(shared,prepared); return true;
        });
    };
    check(commit_richonline_combat_plan(plan,adapter) && plan.committed &&
        ledger.snapshot(0)==shared.actors[0]->funds && ledger.snapshot(1)==shared.actors[1]->funds,
        "ledger_and_session_atomic_commit");
    check(!commit_richonline_combat_plan(stale,adapter) && !stale.committed,"stale_global_revision_rejected");
    rejects([&] { commit_richonline_combat_plan(plan,adapter); },"richonline_combat_session_already_committed");
    auto another=prepare_richonline_boss_combat_turn(shared,map,0,random({90,0,0,0}));
    const auto old=ledger.snapshot(0);
    ledger.adjust(0,old,{1,0,0,0});
    const auto revision=shared.revision;
    bool failed=false;
    try { commit_richonline_combat_plan(another,adapter); } catch (const CodecError&) { failed=true; }
    check(failed && !another.committed && shared.revision==revision &&
        ledger.snapshot(1)==shared.actors[1]->funds,"stale_ledger_no_partial_map_or_other_actor_commit");
}
void live_modifiers_refresh_and_destroyed_building_sources() {
    auto before=state(); auto map=world();
    before.actors[0]->attack_building_source=0;
    before.actors[1]->defense_building_source=0;
    before.buildings={{0,{6,7,11,12},13,2,1,false}};
    map.building=[](const RichonlineCombatBuildingView& building,RichonlineBossBlastBuildingEffect) {
        auto after=building; --after.level; if (!after.level) after.kind=-1; return after;
    };
    map.resolve_terms=[](const RichonlineCombatActorView& actor,const RichonlineCombatSessionView&) {
        RichonlineCombatWorld::ResolvedTerms result{{},{},0,0};
        if (actor.attack_building_source) result.attack.building_multiplier=2.0F;
        if (actor.defense_building_source) result.defense.building_multiplier=0.5F;
        result.flat_attack=actor.funds.funds.cash<9000?100:0;
        return result;
    };
    const auto plan=prepare_richonline_boss_combat_turn(before,map,0,random({90,90,0,0}),{{RichonlineCombatEffect::nuclear}});
    check(!plan.after.actors[0]->attack_building_source && !plan.after.actors[1]->defense_building_source &&
        plan.after.actors[0]->attack_modifiers.building_multiplier==1.0F &&
        plan.after.actors[1]->defense_modifiers.building_multiplier==1.0F,"destroyed_building_buffs_not_cleared");
    check(plan.after.actors[0]->funds.funds.cash==5400 && plan.after.actors[1]->funds.funds.cash==6900,
        "cash_dependent_terms_or_attack_defense_separation");
    check(plan.after.buildings[0].level==0 && plan.after.buildings[0].kind==-1,"successive_building_downgrade");
}
void human_target_cards_are_direct_and_inventory_checked() {
    auto before=state();auto map=world();map.card_targets=map.targets;
    before.actors[0]->inventory[2]={1044,2};
    auto remaining=before.actors[0]->inventory;remaining[2].count=1;
    RichonlineBossCards::PreparedConsumption consume{before.actors[0]->inventory,remaining,2,1044};
    const RichonlineTargetCardRequest request{RichonlineTargetCard::mine1044,7,2,0,12};
    const auto mine=prepare_richonline_combat_human_card(before,map,0,request,7,consume);
    check(mine.packets==std::vector<Bytes>{{0xbd,0x40,0x34,0x12,2,0,12,0}} &&
        mine.after.mines.mines==std::vector<RichonlineMine>{{12,0,3}} &&
        mine.after.actors[0]->inventory==remaining && mine.card_consumptions.size()==1,"human_mine_direct_fields_or_consumption");
    check(before.actors[0]->inventory[2].count==2 && before.mines.mines.empty(),"human_card_prepare_mutated");
    auto bad=request;bad.calendar_counter=8;
    rejects([&] { prepare_richonline_combat_human_card(before,map,0,bad,7,consume); },"richonline_combat_human_card_calendar_mismatch");
    bad=request;bad.inventory_bank=1;
    rejects([&] { prepare_richonline_combat_human_card(before,map,0,bad,7,consume); },"richonline_combat_human_card_fields_invalid");
    bad=request;bad.target=13;
    rejects([&] { prepare_richonline_combat_human_card(before,map,0,bad,7,consume); },"richonline_combat_human_card_target_not_authorized");
    auto corrupt=consume;corrupt.remaining_inventory[2]={};
    rejects([&] { prepare_richonline_combat_human_card(before,map,0,request,7,corrupt); },"richonline_combat_human_card_consumption_invalid");
    auto occupied=before;occupied.dynamic_npcs={{12,3}};
    rejects([&] { prepare_richonline_combat_human_card(occupied,map,0,request,7,consume); },"richonline_combat_human_card_target_occupied");
    auto controlled=before;controlled.actors[0]->status.sleepwalking=1;
    rejects([&] { prepare_richonline_combat_human_card(controlled,map,0,request,7,consume); },"richonline_combat_human_card_actor_controlled");
    before.actors[0]->inventory[2]={1046,1};remaining=before.actors[0]->inventory;remaining[2]={};
    consume={before.actors[0]->inventory,remaining,2,1046};
    const auto missile=prepare_richonline_combat_human_card(before,map,0,{RichonlineTargetCard::missile1046,7,2,0,12},7,consume);
    check(missile.packets==std::vector<Bytes>{{0xbf,0x40,0x34,0x12,2,0,12,0,0,0}} &&
        missile.after.actors[0]->funds.funds.cash==9000 && missile.after.actors[1]->funds.funds.cash==9000 &&
        missile.after.actors[0]->inventory==remaining && missile.funds_updates.size()==2,"human_missile_direct_not_boss_rolls");
    for(const bool safe:{false,true}) {
        before.actors[0]->inventory[2]={static_cast<std::int16_t>(safe?1075:1063),1};
        remaining=before.actors[0]->inventory;remaining[2]={};
        consume={before.actors[0]->inventory,remaining,2,static_cast<std::int16_t>(safe?1075:1063)};
        const auto kind=safe?RichonlineTargetCard::safe_nuclear1075:RichonlineTargetCard::nuclear1063;
        const auto nuclear=prepare_richonline_combat_human_card(before,map,0,{kind,7,2,0,12},7,consume);
        check(nuclear.packets==std::vector<Bytes>{{static_cast<std::uint8_t>(safe?0xd5:0xcc),0x40,0x34,0x12,2,0,12,0,0,0}} &&
            nuclear.after.actors[0]->funds.funds.cash==(safe?10000U:8500U) &&
            nuclear.after.actors[1]->funds.funds.cash==8500 && nuclear.after.actors[0]->inventory==remaining,
            "human_nuclear_or_safe_damage_and_packet");
    }
    for(const auto opcode:{std::uint8_t{124},std::uint8_t{133}}) {
        Bytes wire{opcode,0,7,0,2,0,12,0,0,1};
        const auto decoded=parse_richonline_target_card(wire);
        check(static_cast<std::uint16_t>(decoded.kind)==opcode && decoded.inventory_slot==2 && decoded.target==12,
            "nuclear_typed_request_decode");
        wire[9]=0;
        rejects([&] { parse_richonline_target_card(wire); },"richonline_target_card_constructor_invalid");
        wire.resize(8);
        rejects([&] { parse_richonline_target_card(wire); },"richonline_target_card_wire_invalid");
    }
}
}
int main() {
    try {
        attacks(); mines(); supermines(); helmets_and_buildings(); helmet_limits_exclusions_and_usage_lifetime();
        atomic_commit(); live_modifiers_refresh_and_destroyed_building_sources();
        human_target_cards_are_direct_and_inventory_checked();
        std::cout<<"richonline combat session tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
