#include "richonline_combat_session.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <set>

namespace richnet {
namespace {
constexpr auto maximum=std::numeric_limits<std::int32_t>::max();
bool contains(const std::vector<std::int16_t>& positions,std::int16_t value) {
    return std::ranges::find(positions,value)!=positions.end();
}
void next_revision(std::uint64_t& revision) {
    if (revision==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_combat_session_revision_overflow");
    ++revision;
}
void validate(const RichonlineCombatSessionView& state,const RichonlineCombatWorld& world) {
    const auto size=static_cast<std::uint32_t>(world.width)*world.height;
    if (!world.width || !world.height || size>32768 || !world.step || world.resources.mine_days!=3 ||
        world.resources.mine_range==0 || world.resources.mine_range>2)
        throw CodecError("richonline_combat_session_world_invalid");
    const auto legal=[&](std::int16_t position) { return position>=0 && static_cast<std::uint32_t>(position)<size; };
    for (std::size_t i=0;i<state.actors.size();++i) if (state.actors[i]) {
        const auto& actor=*state.actors[i];
        if (actor.slot!=i || !legal(actor.position) || !actor.funds.funds.deposit ||
            actor.funds.funds.cash>maximum || *actor.funds.funds.deposit>maximum ||
            actor.flat_attack<0 || actor.flat_defense<0)
            throw CodecError("richonline_combat_session_actor_invalid");
    }
    std::set<std::int16_t> dynamic_positions;
    for (const auto& mine:state.mines.mines) {
        if (!legal(mine.position) || mine.owner < -1 || mine.owner>=8 ||
            (mine.owner>=0 && !state.actors[static_cast<std::size_t>(mine.owner)]) ||
            mine.remaining_days==0 || mine.remaining_days>3 ||
            (mine.kind!=RichonlineMineKind::normal && mine.kind!=RichonlineMineKind::super) ||
            !dynamic_positions.insert(mine.position).second)
            throw CodecError("richonline_combat_session_mine_invalid");
    }
    for (const auto& npc:state.dynamic_npcs)
        if (!legal(npc.position) || npc.type==12 || npc.type==27 || !dynamic_positions.insert(npc.position).second)
            throw CodecError("richonline_combat_session_npc_invalid");
    std::set<std::uint32_t> properties;
    std::set<std::int16_t> property_positions;
    for (const auto& building:state.buildings) {
        // Construction resources permit levels through 7; Zhao can upgrade to
        // 6. The shared combat snapshot must accept those committed buildings.
        if (building.footprint.empty() || building.level>7 || !properties.insert(building.property).second ||
            (building.owner && (*building.owner>=8 || !state.actors[*building.owner])))
            throw CodecError("richonline_combat_session_building_invalid");
        for (const auto position:building.footprint)
            if (!legal(position) || !property_positions.insert(position).second)
                throw CodecError("richonline_combat_session_building_invalid");
    }
}
RichonlineCombatTurnPlan initial(const RichonlineCombatSessionView& state,const RichonlineCombatWorld& world) {
    validate(state,world);
    RichonlineCombatTurnPlan plan;
    plan.expected=state; plan.after=state;
    return plan;
}
void finish(RichonlineCombatTurnPlan& plan,bool changed) {
    if (!changed) return;
    next_revision(plan.after.revision);
    if (plan.after.mines!=plan.expected.mines) {
        plan.after.mines.revision=plan.expected.mines.revision;
        next_revision(plan.after.mines.revision);
    }
    for (std::size_t i=0;i<plan.after.actors.size();++i) if (plan.after.actors[i]) {
        auto& after=*plan.after.actors[i];
        const auto& before=*plan.expected.actors[i];
        if (after.funds.funds!=before.funds.funds) {
            plan.funds_updates.push_back({after.slot,before.funds,after.funds.funds});
            next_revision(after.funds.revision);
        }
        if (before.active && !after.active) plan.bankrupt_actors.push_back(after.slot);
    }
}
void debit(RichonlineCombatActorView& actor,std::uint32_t damage) {
    auto& funds=actor.funds.funds;
    const auto total=static_cast<std::uint64_t>(funds.cash)+*funds.deposit;
    const auto cash=std::min(funds.cash,damage);
    funds.cash-=cash;
    *funds.deposit-=std::min(*funds.deposit,damage-cash);
    if (damage>=total) actor.active=false;
}
std::uint32_t damage(const RichonlineCombatSessionView& state,std::int8_t owner,
    const RichonlineCombatActorView& victim,std::uint32_t base) {
    const RichonlineActorStatus neutral_status{};
    const RichonlineCombatModifiers neutral_modifiers{};
    const auto* attacker=owner<0?nullptr:&*state.actors[static_cast<std::size_t>(owner)];
    return calculate_richonline_combat_damage(base,attacker?attacker->status:neutral_status,victim.status,
        attacker?attacker->attack_modifiers:neutral_modifiers,victim.defense_modifiers,
        attacker && attacker->active && attacker->attack_modifiers_enabled,
        attacker?attacker->flat_attack:0,victim.flat_defense);
}
bool mine_exists(const RichonlineCombatSessionView& state,std::int16_t position) {
    return std::ranges::any_of(state.mines.mines,[&](const auto& mine) { return mine.position==position; });
}
void refresh_terms(RichonlineCombatSessionView& state,const RichonlineCombatWorld& world) {
    if (!world.resolve_terms) return;
    for (auto& actor:state.actors) if (actor) {
        const auto terms=world.resolve_terms(*actor,state);
        actor->attack_modifiers=terms.attack; actor->defense_modifiers=terms.defense;
        actor->flat_attack=terms.flat_attack; actor->flat_defense=terms.flat_defense;
    }
}
void chain(RichonlineCombatTurnPlan& plan,const RichonlineCombatWorld& world,std::int16_t root) {
    auto& state=plan.after;
    refresh_terms(state,world);
    const auto size=static_cast<std::uint32_t>(world.width)*world.height;
    const auto checked_step=[&](std::int16_t position,std::uint8_t direction) {
        const auto next=world.step(position,direction);
        if (next && (*next<0 || static_cast<std::uint32_t>(*next)>=size))
            throw CodecError("richonline_combat_session_topology_invalid");
        return next;
    };
    const auto graph=plan_richonline_mine_chain(root,state.mines.mines,world.resources.mine_range,checked_step);
    std::array<std::uint32_t,8> amounts{},raw_amounts{};
    std::uint32_t global_super_hits=0;
    // Compute all victims against the same attack-time snapshot. An earlier
    // victim's bankruptcy must not erase its owner modifier mid-explosion.
    for (const auto& entry:state.actors) if (entry && entry->active && !entry->in_hospital &&
        !entry->in_prison && !entry->status.frozen && !entry->mine_immune_vehicle) {
        std::uint64_t sum=0,raw=0;
        for (const auto& blast:graph.blasts) if (contains(blast.positions,entry->position)) {
            const auto base=blast.mine.kind==RichonlineMineKind::super?
                world.resources.super_mine_damage:world.resources.mine_damage;
            sum+=damage(state,blast.mine.owner,*entry,base);
            raw+=base;
            if (blast.mine.kind==RichonlineMineKind::super) ++global_super_hits;
        }
        if (sum>maximum || raw>maximum) throw CodecError("richonline_combat_session_chain_overflow");
        amounts[entry->slot]=static_cast<std::uint32_t>(sum);
        raw_amounts[entry->slot]=static_cast<std::uint32_t>(raw);
    }
    for (std::size_t i=0;i<amounts.size();++i) if (amounts[i]) {
        amounts[i]=richonline_mixed_mine_chain_damage(amounts[i],raw_amounts[i],global_super_hits,
            world.resources.mine_damage,world.resources.super_mine_damage);
        debit(*state.actors[i],amounts[i]);
    }
    std::erase_if(state.mines.mines,[&](const auto& mine) { return contains(graph.detonated_mines,mine.position); });
    std::erase_if(state.dynamic_npcs,[&](const auto& npc) { return contains(graph.affected_positions,npc.position); });
}
void projectile(RichonlineCombatTurnPlan& plan,const RichonlineCombatWorld& world,
    std::uint8_t boss,RichonlineCombatEffect effect,std::int16_t target) {
    auto& state=plan.after;
    refresh_terms(state,world);
    const auto footprint=richonline_attack_footprint(effect,target,world.width,world.height,world.resources);
    const auto& attacker=*state.actors[boss];
    std::array<std::optional<RichonlineCombatDamagePlan>,8> damages{};
    for (auto& entry:state.actors) if (entry && contains(footprint,entry->position) &&
        richonline_attack_hits_actor(effect,static_cast<std::int8_t>(boss),static_cast<std::int8_t>(entry->slot),
            entry->active,entry->in_hospital,entry->in_prison,entry->status.frozen!=0)) {
        auto helmet=world.helmet?world.helmet(*entry,state):std::nullopt;
        if (helmet && helmet->source_inventory!=entry->inventory)
            throw CodecError("richonline_combat_session_helmet_stale");
        const RichonlineCombatDamageTerms terms{world.resources.base_damage(effect),attacker.flat_attack,
            entry->flat_defense,false,attacker.active && attacker.attack_modifiers_enabled,
            std::array{attacker.attack_modifiers,entry->defense_modifiers}};
        damages[entry->slot]=plan_richonline_combat_damage(entry->slot,entry->funds,effect,attacker.status,
            entry->status,terms,RichonlineClientDamageApplication::by_queued_attack,helmet);
    }
    for (std::size_t i=0;i<damages.size();++i) if (damages[i]) {
        const auto& result=*damages[i];
        auto& actor=*state.actors[i];
        actor.funds.funds=result.after;
        if (result.bankrupt) actor.active=false;
        if (result.safety_helmet_consumption) {
            actor.inventory=result.safety_helmet_consumption->remaining_inventory;
            // The NEW storage is a WORD, including its modulo65536 increment.
            ++actor.status.safety_helmet_uses;
            plan.card_consumptions.push_back({actor.slot,*result.safety_helmet_consumption});
        }
    }
    for (auto& building:state.buildings) if (std::ranges::any_of(building.footprint,
        [&](const auto position) { return contains(footprint,position); })) {
        const auto action=richonline_boss_blast_building_effect(effect,building.kind,building.level,
            building.owner.has_value(),building.ownership_protected);
        if (action==RichonlineBossBlastBuildingEffect::none) continue;
        if (!world.building) throw CodecError("richonline_combat_session_building_adapter_missing");
        auto after=world.building(building,action);
        if (after.property!=building.property || after.footprint!=building.footprint || after.level>7 ||
            (action==RichonlineBossBlastBuildingEffect::remove_ownership && after.owner) ||
            (action==RichonlineBossBlastBuildingEffect::lower_one_level &&
                (after.level+1!=building.level || after.owner!=building.owner)))
            throw CodecError("richonline_combat_session_building_adapter_invalid");
        for (auto& actor:state.actors) if (actor) {
            if (actor->attack_building_source==building.property) {
                actor->attack_building_source.reset();
                actor->attack_modifiers.building_multiplier=1.0F;
            }
            if (actor->defense_building_source==building.property) {
                actor->defense_building_source.reset();
                actor->defense_modifiers.building_multiplier=1.0F;
            }
        }
        building=std::move(after);
    }
    std::erase_if(state.dynamic_npcs,[&](const auto& npc) { return contains(footprint,npc.position); });
    std::vector<std::int16_t> roots;
    for (const auto& mine:state.mines.mines) if (contains(footprint,mine.position)) roots.push_back(mine.position);
    // Client attack animation emits its own mine animation. No extra 4017.
    for (const auto root:roots) if (mine_exists(state,root)) chain(plan,world,root);
}
std::size_t select(const RichonlineBossAttackRandomness& randomness,std::size_t bound) {
    if (!bound || !randomness.bounded) throw CodecError("richonline_combat_session_random_missing");
    const auto result=randomness.bounded(bound);
    if (result>=bound) throw CodecError("richonline_combat_session_random_out_of_range");
    return result;
}
}
RichonlineCombatTurnPlan prepare_richonline_boss_combat_turn(const RichonlineCombatSessionView& before,
    const RichonlineCombatWorld& world,std::uint8_t boss,const RichonlineBossAttackRandomness& randomness,
    const RichonlineBossCombatPolicy& policy) {
    auto plan=initial(before,world);
    if (boss>=8 || !before.actors[boss]) throw CodecError("richonline_combat_session_boss_invalid");
    if (!world.targets || policy.projectiles.empty()) throw CodecError("richonline_combat_session_policy_invalid");
    for (const auto effect:policy.projectiles)
        if (effect!=RichonlineCombatEffect::missile && effect!=RichonlineCombatEffect::nuclear &&
            effect!=RichonlineCombatEffect::safe_nuclear) throw CodecError("richonline_combat_session_policy_invalid");
    for (const auto roll:randomness.rolls)
        if (roll>=100) throw CodecError("richonline_combat_session_roll_invalid");
    bool changed=false;
    for (std::size_t i=0;i<4;++i) {
        auto& attempt=plan.boss_attempts[i];
        const auto& actor=*plan.after.actors[boss];
        if (!actor.active) { attempt.outcome=RichonlineCombatAttemptOutcome::actor_eliminated; continue; }
        if (actor.in_hospital || actor.in_prison || !richonline_combat_action_allowed(actor.status) ||
            actor.status.one_step || actor.status.six_steps || actor.status.turtle || actor.status.stay) {
            attempt.outcome=RichonlineCombatAttemptOutcome::controlled; continue;
        }
        const auto roll=randomness.rolls[i];
        if (roll<80) continue;
        const auto effect=roll<90?RichonlineCombatEffect::mine:
            policy.projectiles[policy.projectiles.size()==1?0:select(randomness,policy.projectiles.size())];
        attempt.effect=effect;
        auto targets=world.targets(boss,effect,plan.after);
        std::set<std::int16_t> unique;
        const auto size=static_cast<std::uint32_t>(world.width)*world.height;
        for (const auto target:targets)
            if (target<0 || static_cast<std::uint32_t>(target)>=size || !unique.insert(target).second)
                throw CodecError("richonline_combat_session_targets_invalid");
        if (effect==RichonlineCombatEffect::mine)
            std::erase_if(targets,[&](const auto target) { return mine_exists(plan.after,target) ||
                std::ranges::any_of(plan.after.dynamic_npcs,[&](const auto& npc) { return npc.position==target; }); });
        if (targets.empty()) { attempt.outcome=RichonlineCombatAttemptOutcome::no_legal_target; continue; }
        const auto target=targets[select(randomness,targets.size())];
        attempt.target=target; attempt.outcome=RichonlineCombatAttemptOutcome::executed;
        plan.packets.push_back(encode_richonline_boss_noninventory_attack(before.game_id,effect,
            static_cast<std::int8_t>(boss),target,actor.status,true));
        if (effect==RichonlineCombatEffect::mine)
            plan.after.mines=plan_richonline_mine_placement(plan.after.mines,target,static_cast<std::int8_t>(boss),true);
        else projectile(plan,world,boss,effect,target);
        changed=true;
    }
    finish(plan,changed);
    return plan;
}
RichonlineCombatTurnPlan prepare_richonline_combat_mine_day(const RichonlineCombatSessionView& before,
    const RichonlineCombatWorld& world,std::uint64_t day,bool round_anchor) {
    auto plan=initial(before,world);
    const auto clock=plan_richonline_mine_day(before.mines,day,before.game_id,round_anchor);
    if (clock.after==before.mines) return plan;
    // Keep the expired roots until chain tracing is complete. The pure clock's
    // independently listed 4017 packets would double-explode connected roots.
    plan.after.mines.last_day=clock.after.last_day;
    plan.packets.push_back(encode_richonline_mine_day401e(before.game_id));
    for (auto& mine:plan.after.mines.mines) --mine.remaining_days;
    for (const auto& mine:clock.expired) if (mine_exists(plan.after,mine.position)) {
        plan.packets.push_back(encode_richonline_mine_explosion4017(before.game_id,mine.position));
        chain(plan,world,mine.position);
    }
    finish(plan,true);
    return plan;
}
RichonlineCombatTurnPlan prepare_richonline_combat_detonate(const RichonlineCombatSessionView& before,
    const RichonlineCombatWorld& world,std::uint8_t actor,const RichonlineBossCards::PreparedConsumption& consumption) {
    auto plan=initial(before,world);
    if(actor!=0 || !before.actors[actor] || !world.detonation_roots)
        throw CodecError("richonline_detonation_authority_required");
    const auto& human=*before.actors[actor];
    if(!human.active || human.in_hospital || human.in_prison || !richonline_combat_action_allowed(human.status))
        throw CodecError("richonline_detonation_actor_controlled");
    if(consumption.source_inventory!=human.inventory || consumption.card_id!=501 || consumption.slot<0 || consumption.slot>=8)
        throw CodecError("richonline_detonation_inventory_invalid");
    const auto roots=world.detonation_roots(actor,before);
    if(roots.empty()) throw CodecError("richonline_detonation_no_visible_mines");
    plan.after.actors[actor]->inventory=consumption.remaining_inventory;
    plan.card_consumptions.push_back({actor,consumption});
    Bytes success;append_le(success,0x40ef,2);append_le(success,before.game_id,2);
    success.push_back(static_cast<std::uint8_t>(consumption.slot));success.insert(success.end(),3,0);
    plan.packets.push_back(std::move(success));
    for(const auto root:roots) if(mine_exists(plan.after,root)) {
        plan.packets.push_back(encode_richonline_mine_explosion4017(before.game_id,root));
        chain(plan,world,root);
    }
    plan.packets.push_back(encode_richonline_dice_recovery400b(before.game_id));
    finish(plan,true);
    return plan;
}
RichonlineCombatTurnPlan prepare_richonline_combat_human_card(const RichonlineCombatSessionView& before,
    const RichonlineCombatWorld& world,std::uint8_t actor,const RichonlineTargetCardRequest& request,
    std::uint16_t calendar,const RichonlineBossCards::PreparedConsumption& consumption) {
    auto plan=initial(before,world);
    if(actor!=0 || !before.actors[actor]) throw CodecError("richonline_combat_human_card_actor_invalid");
    if(request.calendar_counter!=calendar) throw CodecError("richonline_combat_human_card_calendar_mismatch");
    if(request.inventory_slot<0 || request.inventory_slot>=8 || request.inventory_bank!=0 || request.target<0)
        throw CodecError("richonline_combat_human_card_fields_invalid");
    RichonlineCombatEffect effect;std::int16_t card;
    switch(request.kind) {
    case RichonlineTargetCard::mine1044:effect=RichonlineCombatEffect::mine;card=1044;break;
    case RichonlineTargetCard::missile1046:effect=RichonlineCombatEffect::missile;card=1046;break;
    case RichonlineTargetCard::nuclear1063:effect=RichonlineCombatEffect::nuclear;card=1063;break;
    case RichonlineTargetCard::safe_nuclear1075:effect=RichonlineCombatEffect::safe_nuclear;card=1075;break;
    default:throw CodecError("richonline_combat_human_card_kind_invalid");
    }
    const auto& human=*before.actors[actor];
    if(!human.active || human.in_hospital || human.in_prison || !richonline_combat_action_allowed(human.status))
        throw CodecError("richonline_combat_human_card_actor_controlled");
    const auto slot=static_cast<std::size_t>(request.inventory_slot);
    if(consumption.source_inventory!=human.inventory || consumption.slot!=request.inventory_slot ||
        consumption.card_id!=card || human.inventory[slot].card_id!=card || human.inventory[slot].count<=0)
        throw CodecError("richonline_combat_human_card_consumption_stale");
    auto inventory=human.inventory;
    if(--inventory[slot].count==0) inventory[slot]={};
    if(inventory!=consumption.remaining_inventory)
        throw CodecError("richonline_combat_human_card_consumption_invalid");
    if(!world.card_targets) throw CodecError("richonline_combat_human_card_targets_missing");
    const auto targets=world.card_targets(actor,effect,before);
    std::set<std::int16_t> unique;
    const auto area=static_cast<std::uint32_t>(world.width)*world.height;
    for(const auto target:targets)
        if(target<0 || static_cast<std::uint32_t>(target)>=area || !unique.insert(target).second)
            throw CodecError("richonline_combat_human_card_targets_invalid");
    if(!contains(targets,request.target)) throw CodecError("richonline_combat_human_card_target_not_authorized");
    if(effect==RichonlineCombatEffect::mine && (mine_exists(before,request.target) ||
        std::ranges::any_of(before.dynamic_npcs,[&](const auto& npc) { return npc.position==request.target; })))
        throw CodecError("richonline_combat_human_card_target_occupied");
    plan.after.actors[actor]->inventory=inventory;
    plan.card_consumptions.push_back({actor,consumption});
    if(effect==RichonlineCombatEffect::mine) {
        plan.after.mines=plan_richonline_mine_placement(plan.after.mines,request.target,static_cast<std::int8_t>(actor),true);
        plan.packets.push_back(encode_richonline_mine40bd(before.game_id,request));
    } else {
        switch(effect) {
        case RichonlineCombatEffect::missile:
            plan.packets.push_back(encode_richonline_missile40bf(before.game_id,request,static_cast<std::int8_t>(actor)));break;
        case RichonlineCombatEffect::nuclear:
            plan.packets.push_back(encode_richonline_nuclear40cc(before.game_id,request,static_cast<std::int8_t>(actor)));break;
        case RichonlineCombatEffect::safe_nuclear:
            plan.packets.push_back(encode_richonline_safe_nuclear40d5(before.game_id,request,static_cast<std::int8_t>(actor)));break;
        default:throw CodecError("richonline_combat_human_card_kind_invalid");
        }
        projectile(plan,world,actor,effect,request.target);
    }
    finish(plan,true);return plan;
}
RichonlineCombatTurnPlan prepare_richonline_combat_stepped_mine(const RichonlineCombatSessionView& before,
    const RichonlineCombatWorld& world,std::int16_t root) {
    auto plan=initial(before,world);
    chain(plan,world,root);
    finish(plan,true);
    return plan;
}
RichonlineCombatTurnPlan prepare_richonline_combat_fire_landing(const RichonlineCombatSessionView& before,
    const RichonlineCombatWorld& world,std::int8_t owner,std::uint8_t victim,std::int16_t position,
    std::uint32_t base) {
    auto plan=initial(before,world);
    if(owner < -1 || owner>=8 || (owner>=0 && !before.actors[static_cast<std::size_t>(owner)]) ||
        victim>=8 || !before.actors[victim] || !before.actors[victim]->active ||
        before.actors[victim]->position!=position || !world.resolve_terms ||
        !std::ranges::any_of(before.dynamic_npcs,[&](const auto& npc){return npc.position==position && npc.type==26;}))
        throw CodecError("richonline_combat_fire_landing_invalid");
    refresh_terms(plan.after,world);
    auto& target=*plan.after.actors[victim];
    debit(target,damage(plan.after,owner,target,base));
    finish(plan,true);return plan;
}
RichonlineCombatPoisonPlan prepare_richonline_combat_poison(const RichonlineCombatSessionView& before,
    const RichonlineCombatWorld& world,const RichonlineResearchCardRequest& request,
    const RichonlineResearchCardContext& context,std::uint32_t count,const RichonlinePoisonRules& rules,
    std::span<const RichonlinePoisonCell> footprint,std::span<const RichonlineRawActorState> raw) {
    auto combat=initial(before,world);
    if(context.actor<0 || context.actor>=8 || !before.actors[static_cast<std::size_t>(context.actor)] ||
        context.game!=before.game_id || raw.size()!=before.actors.size() || !world.resolve_terms)
        throw CodecError("richonline_combat_poison_context_invalid");
    const auto caster=static_cast<std::uint8_t>(context.actor);
    const auto& hand=before.actors[caster]->inventory;
    const auto initial_plan=plan_richonline_poison_card(request,context,hand,count,rules.base_damage,footprint,{});
    combat.after.actors[caster]->inventory=initial_plan.after_inventory;
    combat.packets.push_back(initial_plan.success);
    std::vector<std::uint8_t> hit;
    // Client processes cells then actors. Re-resolve cash-dependent terms for
    // each occurrence against the updated local funds, without committing yet.
    for(const auto& cell:footprint) for(std::uint8_t slot=0;slot<before.actors.size();++slot) {
        auto& target=combat.after.actors[slot];
        if(!target || !target->active || slot==caster || target->position!=cell.position) continue;
        const auto& eligibility=raw[slot];
        if(!eligibility.hospital1494 || !eligibility.jail1495 || !eligibility.kidnapped1497)
            throw CodecError("richonline_combat_poison_raw_unknown");
        if(*eligibility.hospital1494!=-1 || *eligibility.jail1495!=-1 || *eligibility.kidnapped1497!=-1) continue;
        refresh_terms(combat.after,world);
        const auto amount=damage(combat.after,context.actor,*target,rules.base_damage);
        const RichonlinePoisonVictim victim{slot,cell.position,true,false,false,false,target->funds,amount};
        const auto planned=plan_richonline_poison_card(request,context,hand,count,rules.base_damage,
            std::span{&cell,1},std::span{&victim,1});
        target->funds.funds=planned.funds.at(0).after;
        if(std::ranges::find(hit,slot)==hit.end()) hit.push_back(slot);
    }
    for(const auto slot:hit) {
        auto& target=*combat.after.actors[slot];
        if(target.funds.funds.cash==0 && *target.funds.funds.deposit==0) target.active=false;
    }
    finish(combat,true);
    return {std::move(combat),initial_plan.after_use_count,std::move(hit)};
}
bool commit_richonline_combat_plan(RichonlineCombatTurnPlan& plan,
    const std::function<bool(const RichonlineCombatTurnPlan&)>& atomic_commit) {
    if (plan.committed) throw CodecError("richonline_combat_session_already_committed");
    if (!atomic_commit) throw CodecError("richonline_combat_session_commit_adapter_missing");
    if (plan.after.game_id!=plan.expected.game_id || plan.after.revision<plan.expected.revision)
        throw CodecError("richonline_combat_session_plan_invalid");
    if (!atomic_commit(plan)) return false;
    plan.committed=true;
    return true;
}
}
