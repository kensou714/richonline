#include "richonline_route_effect.hpp"

namespace richnet {
RichonlineRouteStepEffect plan_richonline_route_step_effect(const RichonlineRouteStepContext& step) {
    if(step.position<0) throw CodecError("richonline_route_effect_position_invalid");
    if(step.completed_step==0 || step.movement_budget==0 || step.completed_step>step.movement_budget ||
        step.completed_step>step.available_route_steps || step.available_route_steps>36 || step.movement_budget>36)
        throw CodecError("richonline_route_effect_step_invalid");
    if(step.timed_bomb && (step.timed_bomb->steps_left==0 || step.timed_bomb->steps_left>127 ||
        step.timed_bomb->owner < -1 || step.timed_bomb->owner>=8))
        throw CodecError("richonline_route_effect_bomb_invalid");
    if(step.investment!=RichonlineRouteInvestmentGate::skip && step.investment!=RichonlineRouteInvestmentGate::await_choice &&
        step.investment!=RichonlineRouteInvestmentGate::complete_collection)
        throw CodecError("richonline_route_effect_investment_gate_invalid");
    RichonlineRouteStepEffect result{RichonlineRouteStepKind::walking,{},step.position,step.movement_budget,
        step.timed_bomb,{},{},true,false,false};
    // This is actor1491's step countdown, not a mine's map-day countdown.
    // The branch runs before NPC11/30 and returns before route1456 increments.
    if(step.actor552 && !step.game83830_active && result.timed_bomb_after) {
        if(--result.timed_bomb_after->steps_left==0) {
            result.exploding_bomb_owner=result.timed_bomb_after->owner;
            result.timed_bomb_after.reset(); result.kind=RichonlineRouteStepKind::timed_bomb_stop;
            result.expected_request=0x12; result.advance_route_progress=false;
            if(step.dynamic_type==11 || step.dynamic_type==30) result.removed_dynamic=step.dynamic_type;
            return result;
        }
    }
    // NEW calls60C197 for a live actor-held bomb even when game83830 suppresses
    // countdown. Its precise actor selection belongs to the collision owner.
    result.check_timed_bomb_transfer=step.actor552 && result.timed_bomb_after.has_value();
    if(step.dynamic_type==11) {
        result.kind=RichonlineRouteStepKind::roadblock_stop; result.removed_dynamic=11;
        if(step.actor552) result.expected_request=0x11;
        result.advance_route_progress=false; return result;
    }
    if(step.dynamic_type==30) {
        result.removed_dynamic=30;
        if(result.movement_budget_after==36) throw CodecError("richonline_route_effect_extended_budget_limit");
        ++result.movement_budget_after;
    }
    // A precomputed4011 must already contain every direction NPC30 will use.
    // Issuing another4011 to manufacture an extra step would reset movement.
    if(result.movement_budget_after>step.available_route_steps)
        throw CodecError("richonline_route_effect_direction_budget_exhausted");
    if(step.completed_step>=result.movement_budget_after) {
        result.kind=RichonlineRouteStepKind::ordinary_endpoint;
        if(step.actor552) result.expected_request=0x11;
        return result;
    }
    if(!step.possession7 && !step.actor1499 && !step.game83830_active) {
        if(step.static_type==9 && !step.bank_closed) {
            result.kind=RichonlineRouteStepKind::bank_pause; result.expected_request=0x28;
            result.advance_route_progress=false; return result;
        }
        if(step.static_type==67) {
            if(step.investment==RichonlineRouteInvestmentGate::await_choice) {
                result.kind=RichonlineRouteStepKind::investment_pause; result.expected_request=0x2a;
                result.advance_route_progress=false; return result;
            }
            result.automatic_investment_reward=step.investment==RichonlineRouteInvestmentGate::complete_collection;
        }
    }
    return result;
}
}
