#include "richonline_game_startup.hpp"

#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
void require(bool condition, std::string_view reason) { if (!condition) throw std::runtime_error(std::string(reason)); }
template<class Action> void rejects(Action action, std::string_view expected) {
    try { action(); } catch (const CodecError& error) { require(error.what() == expected,"wrong_rejection"); return; }
    throw std::runtime_error("expected_rejection");
}
const GameAdmission identity{7,19,25,{1,2,3,4,5,6,7,8},0x8b7a6910,{}};
Bytes filler(std::size_t size) { return Bytes(size,0x81); }
Bytes incoming(const Bytes& plain) {
    return encode_frame(richonline_board_frame(plain,{0,-1},filler(plain.size()+2)),
        {Channel::game_c2s,{},ClientVersion::richonline});
}
Bytes decode(const Bytes& packet) {
    return decode_inner(decode_envelope(decode_frame(packet,{Channel::game_s2c,{},ClientVersion::richonline}),
        ClientVersion::richonline).encoded);
}
RichonlineStartupPlan plan(int& ready, int& actions, int& disconnected) {
    return {
        {0x1234,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
            {{25,1,2,{1,2,3,4,5,6,7,8,9,10},0xb1},{-1,9,3,{11,12,13,14,15,16,17,18,19,20},0xb2}}},
        {0x1234,0x88774433,100,{{2000,3000,4},{5000,6000,7}}}, {9,-3},
        [&] { ++ready; return std::vector<Bytes>{}; },
        [&](const Envelope299& envelope,View) {
            require(envelope.inner_type==0 && envelope.mode==-1,"client_envelope_lost");
            ++actions; return std::vector<Bytes>{};
        },
        [&] { ++disconnected; }
    };
}
std::vector<Bytes> admit(GameSession& session) {
    return session.feed(encode_frame(encode_game_admission(identity,ClientVersion::richonline),
        {Channel::game_c2s,{},ClientVersion::richonline}));
}
void ready_signal_is_distinct_from_init_ack_and_counter_is_not_game_id() {
    int ready=0,actions=0,disconnected=0;
    GameSession session(ClientVersion::richonline,make_richonline_game_callbacks(
        [&](const GameAdmission& received)->std::optional<RichonlineStartupPlan> {
            require(received==identity,"admission_mismatch"); return plan(ready,actions,disconnected);
        },filler));
    auto replies=admit(session);
    require(replies.size()==2,"admission_ack_and_init_required");
    const auto ack=decode_frame(replies[0],{Channel::game_s2c,{},ClientVersion::richonline});
    require(ack.wire_type==1 && ack.payload.empty(),"admission_ack_must_precede_init");
    require(read_le(View(decode(replies[1])).first(2))==0x4000,"init_not_sent");
    require(session.feed(incoming({1,0})).empty() && ready==0,"init_ack_started_turn");
    replies=session.feed(incoming({0,0}));
    require(replies.size()==1 && decode(replies[0])==encode_richonline_board_snapshot(plan(ready,actions,disconnected).snapshot),"ready_snapshot_wrong");
    require(ready==1 && session.feed(incoming({0,0})).empty() && ready==1,"duplicate_ready_replayed_start");
    require(session.poll().empty(),"absent_poll_callback_not_optional");
    require(session.feed(incoming({0x10,0,0x33,0x44,6,0,0,0})).empty() && actions==1,"calendar_action_not_accepted");
    rejects([&] { session.feed(incoming({0x10,0,0x34,0x12,6,0,0,0})); },"richonline_game_action_context_mismatch");
    session.finish(); session.finish();
    require(disconnected==1,"startup_cleanup_not_once");
}
void rejects_early_action_and_invalid_identity() {
    int ready=0,actions=0,disconnected=0;
    GameSession early(ClientVersion::richonline,make_richonline_game_callbacks(
        [&](const GameAdmission&)->std::optional<RichonlineStartupPlan> { return plan(ready,actions,disconnected); },filler));
    admit(early);
    rejects([&] { early.feed(incoming({0x10,0,0x33,0x44,1,0,0,0})); },"richonline_game_action_before_map_ready");
    early.finish(); require(actions==0 && disconnected==1,"early_action_changed_world");
    GameSession wrong(ClientVersion::richonline,make_richonline_game_callbacks(
        [&](const GameAdmission&)->std::optional<RichonlineStartupPlan> {
            auto value=plan(ready,actions,disconnected); value.init.participants[0].lobby_identity=26; return value;
        },filler));
    rejects([&] { admit(wrong); },"richonline_game_startup_identity_mismatch");
    wrong.finish(); require(disconnected==2,"invalid_plan_not_released");
}
void turn_context_changes_only_for_normal_turn_and_wraps() {
    int ready=0,actions=0,disconnected=0;
    GameSession session(ClientVersion::richonline,make_richonline_game_callbacks(
        [&](const GameAdmission&)->std::optional<RichonlineStartupPlan> {
            auto value=plan(ready,actions,disconnected);
            value.snapshot.calendar_counter=0xffff;
            value.map_ready=[&] { ++ready; return std::vector<Bytes>{{0x10,0x40,0x34,0x12,0,0,1}}; };
            value.action=[&](const Envelope299&,View) {
                ++actions;
                return actions==1 ? std::vector<Bytes>{{0x10,0x40,0x34,0x12,0,0,0}} : std::vector<Bytes>{};
            };
            return value;
        },filler));
    admit(session);
    require(session.feed(incoming({0,0})).size()==2,"special_turn_missing");
    require(session.feed(incoming({0x15,0,0xff,0xff})).size()==1,"special_turn_changed_counter");
    require(session.feed(incoming({0x10,0,0,0,1,0,0,0})).empty() && actions==2,"normal_turn_did_not_wrap_counter");
    session.finish();
}
void poll_waits_for_map_ready_and_advances_the_action_counter() {
    int ready=0,actions=0,disconnected=0,polls=0;
    auto callbacks=make_richonline_game_callbacks(
        [&](const GameAdmission&)->std::optional<RichonlineStartupPlan> {
            auto value=plan(ready,actions,disconnected);
            value.poll=[&] {
                ++polls;
                return polls==1 ? std::vector<Bytes>{{0x10,0x40,0x34,0x12,0,1,0}} : std::vector<Bytes>{};
            };
            return value;
        },filler);
    GameSession session(ClientVersion::richonline,callbacks);
    require(session.poll().empty() && polls==0,"unadmitted_session_polled_strategy");
    require(!callbacks.poll || callbacks.poll(identity).empty(),"missing_plan_polled_strategy");
    admit(session);
    require(session.poll().empty() && polls==0,"unloaded_map_polled_strategy");
    session.feed(incoming({1,0}));
    require(session.poll().empty() && polls==0,"init_ack_enabled_poll");
    session.feed(incoming({0,0}));
    const auto replies=session.poll();
    require(replies.size()==1 && decode(replies[0])==Bytes({0x10,0x40,0x34,0x12,0,1,0}) && polls==1,"poll_turn_not_sent");
    require(session.feed(incoming({0x10,0,0x34,0x44,1,0,0,0})).empty() && actions==1,"poll_turn_counter_not_advanced");
    require(session.poll().empty() && polls==2,"empty_poll_created_output");
    session.finish();
    require(session.poll().empty() && polls==2 && disconnected==1,"finished_session_polled_strategy");
    require(callbacks.poll(identity).empty() && polls==2,"released_plan_polled_strategy");
}
void invalid_poll_game_id_closes_and_releases_the_session() {
    int ready=0,actions=0,disconnected=0,polls=0;
    GameSession session(ClientVersion::richonline,make_richonline_game_callbacks(
        [&](const GameAdmission&)->std::optional<RichonlineStartupPlan> {
            auto value=plan(ready,actions,disconnected);
            value.poll=[&] { ++polls; return std::vector<Bytes>{{0x10,0x40,0x78,0x56,0,1,0}}; };
            return value;
        },filler));
    admit(session); session.feed(incoming({0,0}));
    rejects([&] { session.poll(); },"richonline_game_response_instance_mismatch");
    require(session.state()==GameState::closed && disconnected==1 && polls==1,"invalid_poll_kept_session_alive");
    require(session.poll().empty() && polls==1 && actions==0,"invalid_poll_reentered_strategy");
    session.finish(); require(disconnected==1,"invalid_poll_repeated_cleanup");
}
void retired_action_is_swallowed_without_changing_the_current_turn() {
    int ready=0,actions=0,disconnected=0,retired=0;
    const Bytes old_request{0x55,0,0x33,0x44,1,0};
    auto callbacks=make_richonline_game_callbacks(
        [&](const GameAdmission&)->std::optional<RichonlineStartupPlan> {
            auto value=plan(ready,actions,disconnected);
            value.poll=[] { return std::vector<Bytes>{{0x10,0x40,0x34,0x12,0,1,0}}; };
            value.retired_action=[&](View plain) {
                ++retired; return Bytes(plain.begin(),plain.end())==old_request;
            };
            return value;
        },filler);
    GameSession session(ClientVersion::richonline,callbacks);
    admit(session); session.feed(incoming({0,0})); session.poll();
    require(session.feed(incoming(old_request)).empty() && retired==1 && actions==0 && session.state()==GameState::admitted,
        "validated_retired_action_not_swallowed");
    require(session.feed(incoming({0x10,0,0x34,0x44,1,0,0,0})).empty() && actions==1 && retired==1,
        "retired_action_changed_counter_or_intercepted_current_action");
    session.finish();
    rejects([&] { session.feed(incoming(old_request)); },"game_session_closed");
    rejects([&] { callbacks.message(identity,{},old_request); },"richonline_game_plan_missing");
    require(retired==1 && actions==1 && disconnected==1,"released_plan_rechecked_retired_action");
}
void unapproved_old_requests_still_fail_context_validation() {
    for (const bool callback_present : {false,true}) {
        int ready=0,actions=0,disconnected=0,retired=0;
        GameSession session(ClientVersion::richonline,make_richonline_game_callbacks(
            [&](const GameAdmission&)->std::optional<RichonlineStartupPlan> {
                auto value=plan(ready,actions,disconnected);
                if (callback_present) value.retired_action=[&](View) { ++retired; return false; };
                return value;
            },filler));
        admit(session); session.feed(incoming({0,0}));
        rejects([&] { session.feed(incoming({0x20,0,0x32,0x44,1,0})); },"richonline_game_action_context_mismatch");
        require(retired==(callback_present ? 1 : 0) && actions==0 && disconnected==1,
            "unapproved_old_request_reached_action");
    }
}
void retired_action_never_bypasses_loading_or_missing_counter() {
    for (const bool loaded : {false,true}) {
        int ready=0,actions=0,disconnected=0,retired=0;
        GameSession session(ClientVersion::richonline,make_richonline_game_callbacks(
            [&](const GameAdmission&)->std::optional<RichonlineStartupPlan> {
                auto value=plan(ready,actions,disconnected);
                value.retired_action=[&](View) { ++retired; return true; };
                return value;
            },filler));
        admit(session);
        if (loaded) session.feed(incoming({0,0}));
        const auto request=loaded ? Bytes{0x20,0,0x32} : Bytes{0x20,0,0x32,0x44,1,0};
        rejects([&] { session.feed(incoming(request)); },loaded ? "richonline_game_action_context_mismatch" : "richonline_game_action_before_map_ready");
        require(retired==0 && actions==0 && disconnected==1,"invalid_boundary_invoked_retirement_policy");
    }
}
}
int main() {
    try { ready_signal_is_distinct_from_init_ack_and_counter_is_not_game_id(); rejects_early_action_and_invalid_identity();
        turn_context_changes_only_for_normal_turn_and_wraps();
        poll_waits_for_map_ready_and_advances_the_action_counter(); invalid_poll_game_id_closes_and_releases_the_session();
        retired_action_is_swallowed_without_changing_the_current_turn(); unapproved_old_requests_still_fail_context_validation();
        retired_action_never_bypasses_loading_or_missing_counter();
        std::cout << "PASS Richonline initialization/loading/context and session poll boundary\n"; }
    catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
