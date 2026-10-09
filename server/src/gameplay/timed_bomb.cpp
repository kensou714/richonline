#include "richonline_timed_bomb.hpp"
#include "original_game_values.hpp"
#include <algorithm>
#include <limits>

namespace richnet {
namespace {
void increment(std::uint64_t& revision) {
    if(revision==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_timed_bomb_revision_overflow");
    ++revision;
}
void rules_valid(const RichonlineTimedBombRules& rules) {
    if(rules.movement_steps==0 || rules.movement_steps>127)
        throw CodecError("richonline_timed_bomb_resource_steps_invalid");
}
void pair_valid(const RichonlineActorStatus& status,const RichonlineCombatSessionView& state) {
    if(status.timed_bomb.has_value()!=status.timed_bomb_owner.has_value())
        throw CodecError("richonline_timed_bomb_pair_missing");
    if(!status.timed_bomb) return;
    if(*status.timed_bomb==0 || *status.timed_bomb>127 || *status.timed_bomb_owner < -1 ||
        *status.timed_bomb_owner>=8 || (*status.timed_bomb_owner>=0 &&
        !state.actors[static_cast<std::size_t>(*status.timed_bomb_owner)]))
        throw CodecError("richonline_timed_bomb_pair_invalid");
}
void validate(const RichonlineCombatSessionView& state,const RichonlineCombatWorld& world,
    const RichonlineTimedBombEligibility& raw) {
    const auto area=static_cast<std::uint32_t>(world.width)*world.height;
    if(!world.width || !world.height || area>32768)
        throw CodecError("richonline_timed_bomb_world_invalid");
    for(std::size_t i=0;i<state.actors.size();++i) {
        if(state.actors[i].has_value()!=raw[i].has_value())
            throw CodecError("richonline_timed_bomb_raw_eligibility_missing");
        if(!state.actors[i]) continue;
        const auto& actor=*state.actors[i];
        if(actor.slot!=i || actor.position<0 || static_cast<std::uint32_t>(actor.position)>=area)
            throw CodecError("richonline_timed_bomb_actor_invalid");
        pair_valid(actor.status,state);
    }
}
RichonlineCombatTurnPlan initial(const RichonlineCombatSessionView& before) {
    RichonlineCombatTurnPlan plan;plan.expected=before;plan.after=before;return plan;
}
void finish(RichonlineCombatTurnPlan& plan) {
    increment(plan.after.revision);
    for(std::size_t i=0;i<plan.after.actors.size();++i) if(plan.after.actors[i]) {
        auto& after=*plan.after.actors[i];const auto& before=*plan.expected.actors[i];
        if(after.funds.funds!=before.funds.funds) {
            plan.funds_updates.push_back({after.slot,before.funds,after.funds.funds});
            increment(after.funds.revision);
        }
        if(before.active && !after.active) plan.bankrupt_actors.push_back(after.slot);
    }
}
void request_valid(const RichonlineTimedBombRequest110& request) {
    if(request.inventory_slot<0 || request.inventory_slot>=8 || request.inventory_bank!=0 ||
        request.target_actor<0 || request.target_actor>=8)
        throw CodecError("richonline_timed_bomb_request_fields_invalid");
}
bool card_target(const RichonlineCombatActorView& target,const RichonlineTimedBombRawEligibility& raw) {
    return target.active && raw.actor1493==-1 && raw.actor1494==-1 &&
        raw.actor1495==-1 && raw.actor1497==-1;
}
void resolve_terms(RichonlineCombatSessionView& state,const RichonlineCombatWorld& world) {
    if(!world.resolve_terms) return;
    for(auto& actor:state.actors) if(actor) {
        const auto terms=world.resolve_terms(*actor,state);
        actor->attack_modifiers=terms.attack;actor->defense_modifiers=terms.defense;
        actor->flat_attack=terms.flat_attack;actor->flat_defense=terms.flat_defense;
    }
}
}
RichonlineTimedBombRules RichonlineTimedBombRules::parse(std::string_view gvalue) {
    const auto values=parse_original_game_values(Bytes(gvalue.begin(),gvalue.end()));
    const auto count=values.require(0);
    if(count<1 || count>127) throw CodecError("richonline_timed_bomb_resource_steps_invalid");
    return {static_cast<std::uint8_t>(count)};
}
RichonlineTimedBombRules RichonlineTimedBombRules::load(const std::filesystem::path& root) {
    const auto values=load_original_game_values(root/"Data/GValue.kpd");
    const auto count=values.require(0);
    if(count<1 || count>127) throw CodecError("richonline_timed_bomb_resource_steps_invalid");
    return {static_cast<std::uint8_t>(count)};
}
RichonlineTimedBombRequest110 decode_richonline_timed_bomb110(View plain) {
    if(plain.size()!=8) throw CodecError("richonline_timed_bomb_request_length");
    if(read_le(plain.first(2))!=110) throw CodecError("richonline_timed_bomb_request_opcode");
    const RichonlineTimedBombRequest110 request{static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),
        static_cast<std::int8_t>(plain[4]),static_cast<std::int8_t>(plain[5]),
        static_cast<std::int8_t>(plain[6]),plain[7]};
    request_valid(request);return request;
}
Bytes encode_richonline_timed_bomb40be(std::uint16_t game,const RichonlineTimedBombRequest110& request,
    std::uint8_t opaque) {
    request_valid(request);Bytes packet;append_le(packet,0x40be,2);append_le(packet,game,2);
    packet.push_back(static_cast<std::uint8_t>(request.inventory_slot));
    packet.push_back(static_cast<std::uint8_t>(request.inventory_bank));
    packet.push_back(static_cast<std::uint8_t>(request.target_actor));packet.push_back(opaque);return packet;
}
RichonlineCombatTurnPlan prepare_richonline_timed_bomb_card(const RichonlineCombatSessionView& before,
    const RichonlineCombatWorld& world,std::uint8_t actor,const RichonlineTimedBombRequest110& request,
    std::uint16_t calendar,const RichonlineTimedBombRules& rules,const RichonlineTimedBombEligibility& raw,
    const RichonlineBossCards::PreparedConsumption& consumption,std::uint8_t opaque) {
    validate(before,world,raw);rules_valid(rules);request_valid(request);
    if(actor>=8 || !before.actors[actor]) throw CodecError("richonline_timed_bomb_action_actor_invalid");
    if(request.calendar_counter!=calendar) throw CodecError("richonline_timed_bomb_calendar_mismatch");
    const auto& source=*before.actors[actor];
    if(!source.active || source.in_hospital || source.in_prison || !richonline_combat_action_allowed(source.status))
        throw CodecError("richonline_timed_bomb_action_actor_controlled");
    const auto target=static_cast<std::size_t>(request.target_actor);
    if(!before.actors[target] || !card_target(*before.actors[target],*raw[target]))
        throw CodecError("richonline_timed_bomb_target_not_authorized");
    const auto slot=static_cast<std::size_t>(request.inventory_slot);
    if(consumption.source_inventory!=source.inventory || consumption.slot!=request.inventory_slot ||
        consumption.card_id!=1045 || source.inventory[slot].card_id!=1045 || source.inventory[slot].count<=0)
        throw CodecError("richonline_timed_bomb_consumption_stale");
    auto inventory=source.inventory;if(--inventory[slot].count==0) inventory[slot]={};
    if(inventory!=consumption.remaining_inventory) throw CodecError("richonline_timed_bomb_consumption_invalid");
    auto plan=initial(before);plan.after.actors[actor]->inventory=inventory;
    auto& status=plan.after.actors[target]->status;status.timed_bomb=rules.movement_steps;
    status.timed_bomb_owner=static_cast<std::int8_t>(actor);
    plan.card_consumptions.push_back({actor,consumption});
    plan.packets.push_back(encode_richonline_timed_bomb40be(before.game_id,request,opaque));
    finish(plan);return plan;
}
RichonlineTimedBombStepPlan prepare_richonline_timed_bomb_step(const RichonlineCombatSessionView& before,
    const RichonlineCombatWorld& world,const RichonlineTimedBombStepContext& context,
    RichonlineTimedBombContinuationPolicy policy) {
    validate(before,world,context.raw);
    if(policy!=RichonlineTimedBombContinuationPolicy::timed_bomb_stop_then_landing)
        throw CodecError("richonline_timed_bomb_continuation_policy_invalid");
    if(context.actor_count==0 || context.actor_count>8 || context.moving_actor>=context.actor_count ||
        !before.actors[context.moving_actor] || !before.actors[context.moving_actor]->active ||
        before.actors[context.moving_actor]->position!=context.actual_position)
        throw CodecError("richonline_timed_bomb_checkpoint_invalid");
    for(std::size_t i=context.actor_count;i<before.actors.size();++i)
        if(before.actors[i]) throw CodecError("richonline_timed_bomb_actor_count_invalid");
    RichonlineTimedBombStepPlan result{initial(before),RichonlineTimedBombStepOutcome::unchanged,{},{},context.actual_position};
    auto& plan=result.combat;auto& mover=*plan.after.actors[context.moving_actor];
    if(!context.actor552 || !mover.status.timed_bomb) return result;
    bool changed=false;
    if(!context.game83830_active) {
        changed=true;result.outcome=RichonlineTimedBombStepOutcome::counted;
        if(--*mover.status.timed_bomb==0) {
            result.outcome=RichonlineTimedBombStepOutcome::exploded;
            result.exploding_owner=mover.status.timed_bomb_owner;
            mover.status.timed_bomb.reset();mover.status.timed_bomb_owner.reset();
            std::erase_if(plan.after.dynamic_npcs,[&](const auto& npc) {
                return npc.position==context.actual_position && (npc.type==11 || npc.type==30);
            });
            resolve_terms(plan.after,world);
            const auto owner=*result.exploding_owner;
            const auto* attacker=owner<0?nullptr:&*plan.after.actors[static_cast<std::size_t>(owner)];
            const RichonlineActorStatus neutral_status{};const RichonlineCombatModifiers neutral_modifiers{};
            const RichonlineCombatDamageTerms terms{world.resources.base_damage(RichonlineCombatEffect::timed_bomb),
                attacker?attacker->flat_attack:0,mover.flat_defense,false,
                attacker && attacker->active && attacker->attack_modifiers_enabled,
                std::array{attacker?attacker->attack_modifiers:neutral_modifiers,mover.defense_modifiers}};
            const auto damage=plan_richonline_combat_damage(context.moving_actor,mover.funds,
                RichonlineCombatEffect::timed_bomb,attacker?attacker->status:neutral_status,mover.status,
                terms,RichonlineClientDamageApplication::already_applied,std::nullopt);
            mover.funds.funds=damage.after;if(damage.bankrupt) mover.active=false;
            // There is no proven official0012 success response. The named policy
            // terminates first; survivors enter the normal landing pipeline.
            if(mover.active) {
                Bytes stop;append_le(stop,0x4013,2);append_le(stop,before.game_id,2);
                append_le(stop,static_cast<std::uint16_t>(context.actual_position),2);
                plan.packets.push_back(std::move(stop));
            }
            finish(plan);return result;
        }
    }
    // NEW7BE930 tests only1493/1497, including during83830 suppression. It does
    // not test1494/1495, and the receiving bomb is not decremented again here.
    for(std::size_t i=0;i<context.actor_count;++i) if(i!=context.moving_actor && plan.after.actors[i]) {
        auto& target=*plan.after.actors[i];const auto& raw=*context.raw[i];
        if(target.active && target.position==context.actual_position && raw.actor1493==-1 && raw.actor1497==-1) {
            std::swap(mover.status.timed_bomb,target.status.timed_bomb);
            std::swap(mover.status.timed_bomb_owner,target.status.timed_bomb_owner);
            result.outcome=RichonlineTimedBombStepOutcome::transferred;
            result.transferred_to=static_cast<std::uint8_t>(i);changed=true;break;
        }
    }
    if(changed) finish(plan);return result;
}
void validate_richonline_timed_bomb_ack12(const RichonlineTimedBombStepPlan& plan,
    const RichonlineMoveCountdown12& request,std::uint16_t calendar) {
    if(plan.outcome!=RichonlineTimedBombStepOutcome::exploded || !plan.exploding_owner || plan.combat.committed)
        throw CodecError("richonline_timed_bomb_ack_without_explosion");
    if(request.calendar_counter!=calendar) throw CodecError("richonline_timed_bomb_ack_calendar_mismatch");
    if(request.endpoint!=plan.actual_stop) throw CodecError("richonline_timed_bomb_ack_position_mismatch");
}
RichonlineTimedBombSegmentPlan prepare_richonline_timed_bomb_segment(const RichonlineCombatSessionView& before,
    const RichonlineCombatWorld& world,std::uint8_t mover,std::span<const RichonlineTimedBombStepContext> steps,
    RichonlineTimedBombContinuationPolicy policy) {
    if(policy!=RichonlineTimedBombContinuationPolicy::timed_bomb_stop_then_landing)
        throw CodecError("richonline_timed_bomb_continuation_policy_invalid");
    if(mover>=8 || !before.actors[mover] || !before.actors[mover]->active)
        throw CodecError("richonline_timed_bomb_segment_actor_invalid");
    if(steps.size()>36) throw CodecError("richonline_timed_bomb_segment_steps_invalid");
    for(const auto& actor:before.actors) if(actor) pair_valid(actor->status,before);
    RichonlineTimedBombSegmentPlan result{initial(before),mover,0,before.actors[mover]->position,{},{}};
    auto projected=before;
    for(const auto& step:steps) {
        if(step.moving_actor!=mover) throw CodecError("richonline_timed_bomb_segment_actor_mismatch");
        // The room has verified topology and pending-route progress. This
        // position exists only in the projection until the whole segment commits.
        projected.actors[mover]->position=step.actual_position;
        auto next=prepare_richonline_timed_bomb_step(projected,world,step,policy);
        ++result.accepted_steps;result.actual_stop=step.actual_position;
        result.outcomes.push_back(next.outcome);
        projected=std::move(next.combat.after);
        // Revisions describe one transaction, not speculative per-step commits.
        projected.revision=before.revision;
        for(std::size_t i=0;i<projected.actors.size();++i) if(projected.actors[i])
            projected.actors[i]->funds.revision=before.actors[i]->funds.revision;
        if(next.outcome==RichonlineTimedBombStepOutcome::exploded) {
            result.exploding_owner=next.exploding_owner;
            result.combat.packets=std::move(next.combat.packets);break;
        }
    }
    result.combat.after=std::move(projected);
    // Even a bomb-free movement consumes its checkpoint once. Empty segments
    // are true no-ops; the bridge token still prevents a second commit.
    if(result.accepted_steps) finish(result.combat);
    return result;
}
void validate_richonline_timed_bomb_segment_ack12(const RichonlineTimedBombSegmentPlan& plan,
    const RichonlineMoveCountdown12& request,std::uint16_t calendar) {
    if(!plan.exploding_owner || plan.accepted_steps==0 || plan.combat.committed)
        throw CodecError("richonline_timed_bomb_ack_without_explosion");
    if(request.calendar_counter!=calendar) throw CodecError("richonline_timed_bomb_ack_calendar_mismatch");
    if(request.endpoint!=plan.actual_stop) throw CodecError("richonline_timed_bomb_ack_position_mismatch");
}
}
