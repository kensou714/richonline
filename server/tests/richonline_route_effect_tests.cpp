#include "richonline_route_effect.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool ok,const char* why) { if(!ok) throw std::runtime_error(why); }
template<class F> void rejects(F action,const char* code) {
    try { action(); } catch(const CodecError& e) { check(std::string(e.what())==code,e.what()); return; }
    throw std::runtime_error("expected_route_effect_rejection");
}
RichonlineRouteStepContext normal() {
    return {173,1,3,3,-1,-1,true,false,false,false,false,{},RichonlineRouteInvestmentGate::skip};
}
void mines_are_not_intermediate_pauses() {
    for(const std::int8_t mine:{std::int8_t{12},std::int8_t{27}}) {
        auto step=normal(); step.dynamic_type=mine;
        const auto pass=plan_richonline_route_step_effect(step);
        check(pass.kind==RichonlineRouteStepKind::walking && !pass.expected_request && !pass.removed_dynamic &&
            pass.advance_route_progress,"map_mine_became_mid_route_pause");
        step.completed_step=3; const auto landing=plan_richonline_route_step_effect(step);
        check(landing.kind==RichonlineRouteStepKind::ordinary_endpoint && landing.expected_request==0x11 &&
            !landing.removed_dynamic,"mine_endpoint_not_sent_to_shared_landing");
    }
}
void timed_bomb_precedes_dynamic_and_static_events() {
    for(const std::int8_t dynamic:{std::int8_t{-1},std::int8_t{11},std::int8_t{30},std::int8_t{12}}) {
        auto step=normal(); step.dynamic_type=dynamic; step.static_type=9; step.timed_bomb=RichonlineRouteTimedBomb{1,1};
        const auto explosion=plan_richonline_route_step_effect(step);
        check(explosion.kind==RichonlineRouteStepKind::timed_bomb_stop && explosion.expected_request==0x12 &&
            explosion.reported_position==173 && explosion.exploding_bomb_owner==1 && !explosion.timed_bomb_after &&
            !explosion.advance_route_progress && explosion.movement_budget_after==3 && !explosion.check_timed_bomb_transfer,
            "timed_bomb_stop_priority_or_countdown_wrong");
        check(explosion.removed_dynamic==(dynamic==11 || dynamic==30 ? std::optional{dynamic} : std::nullopt),
            "timed_bomb_stop_removed_wrong_dynamic");
    }
    auto step=normal(); step.timed_bomb=RichonlineRouteTimedBomb{3,0};
    const auto tick=plan_richonline_route_step_effect(step);
    check(tick.timed_bomb_after && tick.timed_bomb_after->steps_left==2 && !tick.exploding_bomb_owner &&
        tick.check_timed_bomb_transfer,"live_countdown_not_decremented_or_transfer_hidden");
    step.game83830_active=true; const auto suppressed=plan_richonline_route_step_effect(step);
    check(suppressed.timed_bomb_after->steps_left==3 && suppressed.check_timed_bomb_transfer,"suppressed_countdown_was_decremented");
    step.game83830_active=false; step.actor552=false;
    const auto remote=plan_richonline_route_step_effect(step);
    check(remote.timed_bomb_after->steps_left==3 && !remote.check_timed_bomb_transfer,"non_authoritative_actor_countdown_changed");
    step.actor552=true; step.timed_bomb=RichonlineRouteTimedBomb{1,-1};
    check(plan_richonline_route_step_effect(step).exploding_bomb_owner==std::int8_t{-1},
        "unattributed_bomb_owner_was_rejected_or_normalized");
}
void roadblock_stops_before_bank_and_holds_route_progress() {
    for(const bool authoritative:{false,true}) {
        auto step=normal(); step.dynamic_type=11; step.static_type=9; step.actor552=authoritative;
        const auto stop=plan_richonline_route_step_effect(step);
        check(stop.kind==RichonlineRouteStepKind::roadblock_stop && stop.removed_dynamic==11 &&
            !stop.advance_route_progress && stop.expected_request==(authoritative ? std::optional<std::uint16_t>{0x11} : std::nullopt),
            "roadblock_sent_bank_pause_or_advanced_route");
    }
}
void extra_step_is_added_before_checking_for_remaining_route() {
    auto step=normal(); step.completed_step=3; step.dynamic_type=30; step.available_route_steps=4;
    const auto extended=plan_richonline_route_step_effect(step);
    check(extended.kind==RichonlineRouteStepKind::walking && extended.movement_budget_after==4 && extended.removed_dynamic==30 &&
        extended.advance_route_progress && !extended.expected_request,"npc30_did_not_extend_last_dice_step");
    step.static_type=9; const auto bank=plan_richonline_route_step_effect(step);
    check(bank.kind==RichonlineRouteStepKind::bank_pause && bank.expected_request==0x28 && !bank.advance_route_progress &&
        bank.movement_budget_after==4 && bank.removed_dynamic==30,"extended_step_failed_to_pause_at_bank");
    step.available_route_steps=3;
    rejects([&]{plan_richonline_route_step_effect(step);},"richonline_route_effect_direction_budget_exhausted");
    step.completed_step=36; step.movement_budget=36; step.available_route_steps=36;
    rejects([&]{plan_richonline_route_step_effect(step);},"richonline_route_effect_extended_budget_limit");
}
void only_intermediate_eligible_statics_emit_pause_requests() {
    for(const std::int8_t type:{std::int8_t{9},std::int8_t{67}}) {
        auto step=normal(); step.static_type=type; step.investment=RichonlineRouteInvestmentGate::await_choice;
        const auto pause=plan_richonline_route_step_effect(step);
        check(pause.kind==(type==9 ? RichonlineRouteStepKind::bank_pause : RichonlineRouteStepKind::investment_pause) &&
            pause.expected_request==(type==9 ? 0x28 : 0x2a) && !pause.advance_route_progress,"eligible_static_did_not_pause");
        step.completed_step=3; const auto final=plan_richonline_route_step_effect(step);
        check(final.kind==RichonlineRouteStepKind::ordinary_endpoint && final.expected_request==0x11 &&
            !final.automatic_investment_reward,"final_static_was_treated_as_passing");
        for(unsigned blocked=0;blocked<3;++blocked) {
            auto guarded=normal(); guarded.static_type=type; guarded.investment=RichonlineRouteInvestmentGate::await_choice;
            guarded.possession7=blocked==0; guarded.actor1499=blocked==1; guarded.game83830_active=blocked==2;
            const auto skipped=plan_richonline_route_step_effect(guarded);
            check(skipped.kind==RichonlineRouteStepKind::walking && !skipped.expected_request &&
                skipped.advance_route_progress,"static_guard_ignored");
        }
    }
    auto step=normal(); step.static_type=9; step.bank_closed=true;
    check(plan_richonline_route_step_effect(step).kind==RichonlineRouteStepKind::walking,"closed_bank_paused");
    step.static_type=67; step.investment=RichonlineRouteInvestmentGate::complete_collection;
    const auto reward=plan_richonline_route_step_effect(step);
    check(reward.kind==RichonlineRouteStepKind::walking && !reward.expected_request && reward.automatic_investment_reward,
        "complete_collection_created_fake_request");
    step.investment=RichonlineRouteInvestmentGate::skip;
    check(!plan_richonline_route_step_effect(step).automatic_investment_reward,"ineligible_investment_awarded_money");
}
void invalid_step_and_countdown_are_not_silently_normalized() {
    auto step=normal(); step.position=-1;
    rejects([&]{plan_richonline_route_step_effect(step);},"richonline_route_effect_position_invalid");
    for(const std::array<std::uint8_t,3> values:{std::array<std::uint8_t,3>{0,3,3},{4,3,4},{1,0,1},{1,3,0},{1,37,37},{1,3,37}}) {
        step=normal(); step.completed_step=values[0]; step.movement_budget=values[1]; step.available_route_steps=values[2];
        rejects([&]{plan_richonline_route_step_effect(step);},"richonline_route_effect_step_invalid");
    }
    for(const RichonlineRouteTimedBomb bomb: {RichonlineRouteTimedBomb{0,0},{128,0},{1,8},{1,-2}}) {
        step=normal(); step.timed_bomb=bomb;
        rejects([&]{plan_richonline_route_step_effect(step);},"richonline_route_effect_bomb_invalid");
    }
    step=normal(); step.investment=static_cast<RichonlineRouteInvestmentGate>(99);
    rejects([&]{plan_richonline_route_step_effect(step);},"richonline_route_effect_investment_gate_invalid");
}
}
int main() {
    try {
        mines_are_not_intermediate_pauses(); timed_bomb_precedes_dynamic_and_static_events();
        roadblock_stops_before_bank_and_holds_route_progress(); extra_step_is_added_before_checking_for_remaining_route();
        only_intermediate_eligible_statics_emit_pause_requests(); invalid_step_and_countdown_are_not_silently_normalized();
        std::cout<<"PASS NEW route-step priorities, actual pauses and full direction budgets\n";
    } catch(const std::exception& e) { std::cerr<<"FAIL "<<e.what()<<'\n'; return 1; }
}
