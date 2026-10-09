#include "richonline_raw_authority.hpp"
#include "richonline_timed_bomb.hpp"
#include "richonline_game_startup.hpp"

#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
template<class F> void rejects(F&& operation, std::string_view code) {
    try { operation(); }
    catch (const CodecError& error) {
        require(error.what() == code, "wrong_rejection");
        return;
    }
    throw std::runtime_error("expected_rejection");
}

RichonlineRawAuthority initialized() {
    RichonlineRawAuthority state(2, 7);
    state.initialize_game(); state.initialize_actor(0); state.initialize_actor(1);
    return state;
}

void unknown_is_not_default() {
    RichonlineRawAuthority state(2, 7);
    require(!state.game().scripted_event83830, "uninitialized_game");
    require(state.timed_bomb_target(0).capability == RichonlineRawCapability::actor_unknown, "uninitialized_actor");
    rejects([&] { state.enter_hotel(0, 2); }, "richonline_raw_actor_unknown");
    rejects([&] { state.apply_s2c420c(7, 11); }, "richonline_raw_game_unknown");
    state.initialize_actor(0);
    require(state.timed_bomb_countdown(0).capability == RichonlineRawCapability::game_unknown, "game_gate");
    state.initialize_game();
    require(state.timed_bomb_countdown(0).allowed(), "known_constructor_fields");
    require(state.timed_bomb_target(1).capability == RichonlineRawCapability::actor_unknown, "other_actor_not_invented");
    rejects([&] { state.initialize_actor(0); }, "richonline_raw_actor_already_initialized");
    rejects([&] { state.initialize_game(); }, "richonline_raw_game_already_initialized");
    rejects([&] { static_cast<void>(state.actor(2)); }, "richonline_raw_actor_invalid");
    rejects([] { RichonlineRawAuthority invalid(0, 7); }, "richonline_raw_actor_count_invalid");
    rejects([] { RichonlineRawAuthority invalid(9, 7); }, "richonline_raw_actor_count_invalid");
}

void distinct_predicates_and_clocks() {
    auto state = initialized();
    state.enter_hotel(0, 3);
    state.enter_hospital(0, 2);
    require(state.actor(0).hotel1493 == -1, "hospital_clears_hotel");
    require(!state.timed_bomb_target(0).allowed(), "hospital_disallows_target");
    require(state.timed_bomb_transfer_target(0).allowed(), "hospital_not_transfer_guard");
    require(state.timed_bomb_countdown(0).allowed(), "countdown_not_target_predicate");
    state.enter_jail(1, 4); state.enter_kidnapped(1, 2);
    require(!state.timed_bomb_transfer_target(1).allowed(), "kidnap_transfer_guard");
    require(state.apply_verified_actor_timer_phase(0, 10), "first_actor_phase");
    require(state.actor(0).hospital1494 == 1 && state.actor(1).jail1495 == 4, "actor_phase_only_one_actor");
    require(!state.apply_verified_actor_timer_phase(0, 10), "duplicate_actor_phase");
    rejects([&] { static_cast<void>(state.apply_verified_actor_timer_phase(0, 9)); }, "richonline_raw_actor_phase_stale");
    require(state.apply_verified_calendar_advance(1), "first_day");
    require(state.actor(0).hospital1494 == 1 && state.actor(1).jail1495 == 4, "calendar_not_status_clock");
    state.apply_verified_actor_timer_phase(0, 12);
    state.apply_verified_actor_timer_phase(0, 14);
    require(state.actor(0).hospital1494 == 0 && !state.timed_bomb_target(0).allowed(), "zero_not_cleared");
    state.exit_hospital(0);
    require(state.timed_bomb_target(0).allowed(), "explicit_exit_clears");
    require(state.timed_bomb_countdown(0).capability == RichonlineRawCapability::movement_reporting_disabled, "exit_relocation");
    state.apply_s2c4011_movement(0);
    require(state.timed_bomb_countdown(0).allowed(), "4011_resumes_reporting");
    state.exit_kidnapped(1);
    require(state.timed_bomb_transfer_target(1).allowed() && !state.timed_bomb_target(1).allowed(), "jail_not_transfer_guard");
    rejects([&] { state.enter_hospital(0, -1); }, "richonline_raw_duration_invalid");
    require(state.actor(0).hospital1494 == -1, "bad_enter_atomic");
    state.begin_hotel_relocation(0);
    require(state.actor(0).hotel1493 == -1 && state.actor(0).movement_reporting552 == false, "hotel_start_before_entry");
    state.enter_hotel(0, 127);
    state.apply_verified_actor_timer_phase(0, 16);
    require(state.actor(0).hotel1493 == 126, "raw_positive_decrement");
    state.exit_hotel(0); state.exit_jail(1);
    require(state.actor(0).movement_reporting552 == false && state.actor(1).movement_reporting552 == false, "relocation_flags");
}

void unresolved_chest_stays_active() {
    auto state = initialized();
    rejects([&] { state.apply_s2c420c(8, 11); }, "richonline_raw_gmsv_mismatch");
    rejects([&] { state.apply_s2c420c(7, -1); }, "richonline_raw_scripted_position_invalid");
    require(state.game().scripted_event83830 == -1 && !state.game().scripted_event_position, "invalid_chest_atomic");
    state.apply_s2c420c(7, 11);
    require(state.game().scripted_event83830 == 2 && state.game().scripted_event_position == 11, "420c_set2");
    require(state.timed_bomb_target(0).allowed() && state.timed_bomb_transfer_target(1).allowed(), "chest_only_countdown_gate");
    state.apply_verified_actor_timer_phase(0, 1);
    require(state.game().scripted_event83830 == 2, "actor_turn_does_not_age_chest");
    state.apply_verified_calendar_advance(1);
    require(state.game().scripted_event83830 == 1, "first_real_day");
    require(!state.apply_verified_calendar_advance(1) && state.game().scripted_event83830 == 1, "duplicate_day");
    rejects([&] { static_cast<void>(state.apply_verified_calendar_advance(0)); }, "richonline_raw_calendar_phase_stale");
    state.apply_verified_calendar_advance(2); state.apply_verified_calendar_advance(3);
    require(state.game().scripted_event83830 == 0, "no_invented_reset");
    require(state.timed_bomb_countdown(0).capability == RichonlineRawCapability::scripted_event_active, "zero_active");
    rejects([&] { state.initialize_game(); }, "richonline_raw_game_already_initialized");
    require(state.game().scripted_event83830 == 0, "cannot_reinitialize_away_chest");
}

void invalidation_and_prepared_copy() {
    auto state = initialized();
    auto draft = state;
    draft.enter_hospital(0, 2); draft.apply_s2c420c(7, 11);
    require(state.timed_bomb_target(0).allowed() && state.timed_bomb_countdown(0).allowed(), "draft_does_not_mutate_authority");
    state.invalidate_actor(1);
    require(!state.actor(1).hotel1493 && !state.actor(1).movement_reporting552, "invalidated_is_unknown");
    require(state.timed_bomb_transfer_target(1).capability == RichonlineRawCapability::actor_unknown, "transfer_unknown");
    rejects([&] { static_cast<void>(state.apply_verified_actor_timer_phase(1, 1)); }, "richonline_raw_state_unknown");
    rejects([&] { state.initialize_actor(1); }, "richonline_raw_actor_already_initialized");
    state.enter_hospital(1, 2);
    require(state.actor(1).hotel1493 == -1 && !state.actor(1).jail1495, "setter_restores_only_written_fields");
    rejects([&] { static_cast<void>(state.apply_verified_actor_timer_phase(1, 1)); }, "richonline_raw_state_unknown");
    require(state.actor(1).hospital1494 == 2, "unknown_phase_does_not_partially_decrement");
    state.invalidate_game();
    require(state.timed_bomb_countdown(0).capability == RichonlineRawCapability::game_unknown, "invalidated_game_gate");
    rejects([&] { static_cast<void>(state.apply_verified_calendar_advance(1)); }, "richonline_raw_game_unknown");
    rejects([&] { state.initialize_game(); }, "richonline_raw_game_already_initialized");
}

RichonlineStartupPlan startup_plan() {
    RichonlineStartupPlan plan{};
    plan.init.game_server_id=7;
    plan.init.participants.resize(2);
    return plan;
}

void real_startup_binding_observes_complete_frames() {
    auto first=startup_plan();
    std::size_t sent_calls=0,closed_calls=0;
    first.sent=[&](View) { ++sent_calls; };
    first.disconnected=[&] { ++closed_calls; };
    const auto authority=attach_richonline_raw_authority(first);
    auto second=startup_plan();
    const auto independent=attach_richonline_raw_authority(second);
    require(authority->game().scripted_event83830==-1 && authority->timed_bomb_target(1).allowed(), "binding_constructor_state");
    authority->exit_hospital(1);
    Bytes movement(28,0); movement[0]=0x11; movement[1]=0x40; movement[2]=7;
    rejects([&] { first.sent(movement); }, "richonline_raw_current_actor_unknown");
    require(sent_calls==0 && authority->actor(1).movement_reporting552==false, "unknown_actor_not_committed");
    const Bytes turn{0x10,0x40,7,0,1,1,0,0xa2};
    first.sent(turn);
    first.sent(movement);
    require(sent_calls==2 && authority->actor(1).movement_reporting552==true, "sent4010_identifies4011_actor");
    const Bytes event{0x0c,0x42,7,0,11,0,0xa1,0xb2};
    require(authority->game().scripted_event83830==-1, "planned_frame_is_not_delivery");
    first.sent(event);
    require(sent_calls==3 && authority->game().scripted_event83830==2 &&
        authority->game().scripted_event_position==11, "sent420c_reads_known_prefix_with_tail");
    require(independent->game().scripted_event83830==-1 && independent->timed_bomb_countdown(1).allowed(), "startup_rooms_isolated");
    first.sent(Bytes{0x1c,0x40,7,0,9,11,0,0,0});
    require(sent_calls==4 && authority->game().scripted_event83830==2, "ticket_chest_not420c");
    rejects([&] { first.sent(Bytes{0x0c,0x42,8,0,11,0}); }, "richonline_raw_gmsv_mismatch");
    rejects([&] { first.sent(Bytes{0x0c,0x42,7,0,0xff,0xff}); }, "richonline_raw_scripted_position_invalid");
    rejects([&] { first.sent(Bytes{0x10,0x40,7,0,2,1,0,0xa2}); }, "richonline_raw_actor_invalid");
    require(sent_calls==4 && authority->game().scripted_event_position==11, "invalid_frame_does_not_commit");
    first.disconnected(); first.disconnected();
    require(closed_calls==2 && !authority->game().scripted_event83830 && !authority->actor(0).hotel1493, "disconnect_composes_and_invalidates");
    require(independent->game().scripted_event83830==-1, "disconnect_does_not_poison_other_room");
    rejects([&] { first.sent(event); }, "richonline_raw_game_unknown");
}

void delivery_survives_original_observer_failure_then_invalidates() {
    auto plan=startup_plan();
    plan.sent=[](View) { throw CodecError("original_sent_failed"); };
    plan.disconnected=[] { throw CodecError("original_close_failed"); };
    const auto authority=attach_richonline_raw_authority(plan);
    rejects([&] { plan.sent(Bytes{0x0c,0x42,7,0,11,0}); }, "original_sent_failed");
    // The transport already sent the whole frame before this callback. A
    // later settlement observer failure cannot undo the client's mutation.
    require(authority->game().scripted_event83830==2, "sent_failure_cannot_undo_delivered_frame");
    rejects([&] { plan.disconnected(); }, "original_close_failed");
    require(!authority->game().scripted_event83830 && !authority->actor(1).hospital1494, "cleanup_invalidates_before_close_failure");
}

void timed_bomb_projection_preserves_known_values_and_rejects_unknowns() {
    auto state=initialized();
    const auto initial=state.timed_bomb_step_context(1,27);
    require(initial.moving_actor==1 && initial.actor_count==2 && initial.actual_position==27 &&
        initial.actor552 && !initial.game83830_active && initial.raw[0] && initial.raw[1] && !initial.raw[2],
        "initial_step_projection_shape");
    require(initial.raw[0]->actor1493==-1 && initial.raw[0]->actor1494==-1 &&
        initial.raw[0]->actor1495==-1 && initial.raw[0]->actor1497==-1,"initial_step_raw_values");
    state.enter_jail(1,2);state.begin_hotel_relocation(1);state.apply_s2c420c(7,11);
    const auto changed=state.timed_bomb_step_context(1,28);
    require(!changed.actor552 && changed.game83830_active && changed.raw[1]->actor1495==2 &&
        initial.actor552 && !initial.game83830_active && initial.raw[1]->actor1495==-1,
        "projection_must_be_immutable_and_preserve_nondefault_states");
    state.apply_verified_calendar_advance(1);state.apply_verified_calendar_advance(2);
    require(state.timed_bomb_step_context(0,1).game83830_active,"script_zero_is_not_normal");
    rejects([&] { static_cast<void>(state.timed_bomb_step_context(2,1)); },"richonline_raw_actor_invalid");
    rejects([&] { static_cast<void>(state.timed_bomb_step_context(0,-1)); },"richonline_raw_step_position_invalid");
    state.invalidate_actor(1);
    rejects([&] { static_cast<void>(state.timed_bomb_step_context(0,1)); },"richonline_raw_state_unknown");
    rejects([&] { static_cast<void>(state.timed_bomb_step_context(1,1)); },"richonline_raw_movement_unknown");
    state=initialized();state.invalidate_game();
    rejects([&] { static_cast<void>(state.timed_bomb_step_context(0,1)); },"richonline_raw_game_unknown");
}
}

int main() {
    unknown_is_not_default(); distinct_predicates_and_clocks();
    unresolved_chest_stays_active(); invalidation_and_prepared_copy();
    real_startup_binding_observes_complete_frames();
    delivery_survives_original_observer_failure_then_invalidates();
    timed_bomb_projection_preserves_known_values_and_rejects_unknowns();
    std::cout << "raw authority tests passed\n";
}
