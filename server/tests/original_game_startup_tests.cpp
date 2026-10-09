#include "original_game_startup_test_support.hpp"
#include "original_game_registry.hpp"

#include <iostream>

namespace {
using namespace original_startup_test;

void tcp_original_startup_and_isolated_rejections() {
    OriginalGameRegistry registry;
    Counts counts;
    Running running([&] {
        return make_original_game_callbacks([&](const GameAdmission& admission) {
            return registry.consume(admission,AdmissionClock::now());
        });
    });
    const auto port = running.service.bound_port();
    const auto reserve = [&](std::int16_t self) {
        const auto now = AdmissionClock::now();
        const auto redirect = registry.prepare({static_cast<std::uint64_t>(self),
            {9,13,static_cast<std::uint32_t>(self)},{{127,0,0,1},port},now+std::chrono::minutes(1)},plan(counts,self),now);
        require(read_le(View(redirect.payload).subspan(4,2)) == port,"redirect_port_wrong");
        return admission_from_redirect(redirect,static_cast<std::uint32_t>(self));
    };
    const auto first_ticket = reserve(25);
    const auto second_ticket = reserve(26);
    const Client second(port);
    second.send(ticket(second_ticket));
    require(second.plain() == expected_init(26),"second_initialization_not_exact");
    for (int field = 0; field < 7; ++field) {
        auto wrong = first_ticket;
        switch (field) {
        case 0: ++wrong.id0; break;
        case 1: ++wrong.id1; break;
        case 2: wrong.id2 = second_ticket.id2; break;
        case 3: wrong.opaque8[0] ^= 0x80; break;
        case 4: ++wrong.field20; break;
        case 5: ++(*wrong.legacy_fields)[0]; break;
        case 6: ++(*wrong.legacy_fields)[1]; break;
        }
        const Client rejected(port); rejected.send(ticket(wrong)); rejected.closed();
    }
    const Client first(port);
    const auto admission = ticket(first_ticket);
    for (const auto byte : admission) first.send(View(&byte,1));
    require(first.plain() == expected_init(),"first_initialization_fields_or_opaque_lost");
    const Client replay(port); replay.send(admission); replay.closed();

    auto loaded = message(Bytes{1,0});
    const auto map_ready = message(Bytes{0,0});
    loaded.insert(loaded.end(),map_ready.begin(),map_ready.end());
    first.send(loaded);
    require(first.plain() == expected_snapshot(),"load_ack_emitted_snapshot_or_snapshot_fields_lost");
    require(first.plain() == turn,"opening_turn_missing_after_snapshot");
    require(counts.ready.load() == 1,"map_ready_callback_count_wrong");

    auto repeated = loaded;
    const auto action_zero = message(Bytes{3,0,0,0,0x81,0x92});
    repeated.insert(repeated.end(),action_zero.begin(),action_zero.end());
    first.send(repeated);
    require(first.plain() == opaque_result,"duplicate_load_reset_snapshot_or_action_opaque_lost");
    require(first.plain() == turn,"action_turn_missing");
    auto after_turn = loaded;
    const auto action_one = message(Bytes{3,0,1,0,0x83,0x94});
    after_turn.insert(after_turn.end(),action_one.begin(),action_one.end());
    first.send(after_turn);
    require(first.plain() == opaque_result && first.plain() == turn,"duplicate_load_reset_current_context");
    first.send(message(Bytes{2,0}));
    require(first.plain() == opaque_result,"event_callback_opaque_lost");
    require(counts.ready.load() == 1 && counts.actions.load() == 2 && counts.events.load() == 1,
            "duplicate_ready_reopened_strategy_or_event_not_dispatched");

    second.send(map_ready);
    require(second.plain() == expected_snapshot() && second.plain() == turn,"rejected_peers_disrupted_second_startup");
    second.send(action_zero);
    require(second.plain() == opaque_result && second.plain() == turn,"first_player_context_leaked_to_second");
    first.send(message(Bytes{10,0})); first.closed();
    require(counts.released.load() == 1,"leave_did_not_release_once");

    const Client wrong_context(port);
    wrong_context.send(ticket(reserve(27)));
    require(wrong_context.plain() == expected_init(27),"wrong_context_client_admission_failed");
    wrong_context.send(map_ready);
    require(wrong_context.plain() == expected_snapshot() && wrong_context.plain() == turn,"context_fixture_start_failed");
    wrong_context.send(message(Bytes{3,0,0xff,0xff})); wrong_context.closed();
    for (const auto self : {std::int16_t{28},std::int16_t{29}}) {
        const Client early(port); early.send(ticket(reserve(self)));
        require(early.plain() == expected_init(static_cast<std::uint8_t>(self)),"early_client_admission_failed");
        early.send(message(self == 28 ? Bytes{3,0,0xff,0xff} : Bytes{2,0})); early.closed();
    }
    second.send(message(Bytes{10,0})); second.closed();
    running.finish();
    require(counts.released.load() == 5,"startup_release_missing_or_duplicated");
    require(counts.ready.load() == 3 && counts.actions.load() == 3 && counts.events.load() == 1,
            "invalid_client_reached_strategy");
}

void invalid_strategy_output_closes_and_releases() {
    const std::vector<std::pair<Bytes,const char*>> failures{
        {{0,0x40,0x56,0x34},"original_game_duplicate_initialization"},
        {{0x11,0x40,0x57,0x34},"original_game_response_instance_mismatch"},
        {{0x10,0x40,0x56,0x34,0,0},"original_game_turn_truncated"},
        {{0x10,0x40,0x56,0x34,0xff,0,0},"original_game_turn_slot_invalid"},
        {{0x10,0x40,0x56,0x34,0,0xff,1},"original_game_turn_slot_invalid"},
        {{4,0x40,0x56,0x34,1,0,0,0,3,0,0,0},"original_game_snapshot_truncated"}
    };
    for (const auto& [response,code] : failures) {
        Counts counts;
        auto policy = plan(counts);
        policy.map_ready = [response] { return std::vector<Bytes>{response}; };
        GameSession session(ClientVersion::legacy,direct_callbacks(std::move(policy)));
        require(session.feed(ticket(direct_admission())).size() == 1,"direct_admission_failed");
        rejects([&] { session.feed(message(Bytes{0,0})); },code);
        require(session.state() == GameState::closed,"invalid_strategy_kept_session_open");
        session.finish(); session.finish();
        require(counts.released.load() == 1 && counts.actions.load() == 0,"invalid_strategy_cleanup_wrong");
    }
    Counts counts;
    auto policy = plan(counts);
    auto response = expected_snapshot();
    std::fill(response.begin()+8,response.begin()+12,0);
    policy.map_ready = [response] { return std::vector<Bytes>{response}; };
    GameSession session(ClientVersion::legacy,direct_callbacks(std::move(policy)));
    session.feed(ticket(direct_admission()));
    rejects([&] { session.feed(message(Bytes{0,0})); },"original_board_scale_invalid");
    session.finish(); require(counts.released.load() == 1,"zero_scale_cleanup_wrong");
}

void callback_failure_and_invalid_admission_plan_release_once() {
    Counts counts;
    {
        auto policy = plan(counts);
        policy.map_ready = []() -> std::vector<Bytes> { throw CodecError("fixture_map_ready_failure"); };
        GameSession session(ClientVersion::legacy,direct_callbacks(std::move(policy)));
        session.feed(ticket(direct_admission()));
        rejects([&] { session.feed(message(Bytes{0,0})); },"fixture_map_ready_failure");
        session.finish(); session.finish();
        require(counts.released.load() == 1,"throwing_map_ready_cleanup_wrong");
    }
    require(counts.released.load() == 1,"callback_destructor_released_twice");
    for (int invalid = 0; invalid < 3; ++invalid) {
        auto policy = plan(counts);
        const char* code = nullptr;
        switch (invalid) {
        case 0: policy.startup.init.players.front().lobby_user_id = 26; code = "original_game_startup_identity_mismatch"; break;
        case 1: policy.action = {}; code = "original_game_strategy_required"; break;
        case 2: policy.startup.snapshot.gmsv_id = 7; code = "original_board_startup_instance_mismatch"; break;
        }
        GameSession session(ClientVersion::legacy,direct_callbacks(std::move(policy)));
        rejects([&] { session.feed(ticket(direct_admission())); },code);
        require(counts.released.load() == invalid+2,"authorization_failure_did_not_release_immediately");
        session.finish(); session.finish();
    }
    require(counts.released.load() == 4,"failed_authorization_destructor_released_twice");
}
}

int main() {
    try {
        const Network network;
        tcp_original_startup_and_isolated_rejections();
        invalid_strategy_output_closes_and_releases();
        callback_failure_and_invalid_admission_plan_release_once();
        std::cout << "PASS original startup real TCP admission, map-ready, context, isolation and cleanup boundaries.\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
