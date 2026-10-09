#include "original_game_startup_test_support.hpp"

#include <iostream>
#include <type_traits>

namespace {
using namespace original_startup_test;

Bytes plain_response(const Bytes& packet) {
    return decode_inner(decode_envelope(decode_frame(packet,{Channel::game_s2c,{},ClientVersion::legacy})).encoded);
}

void poll_waits_for_map_ready_and_advances_action_context() {
    Counts counts;
    int polls = 0;
    auto strategy = plan(counts);
    strategy.poll = [&] { ++polls; return std::vector<Bytes>{turn}; };
    GameSession session(ClientVersion::legacy,direct_callbacks(std::move(strategy)));
    require(session.poll().empty() && polls == 0,"poll_before_admission");
    require(session.feed(ticket(direct_admission())).size() == 1,"poll_fixture_admission");
    require(session.poll().empty() && polls == 0,"poll_before_map_ready");
    session.feed(message(Bytes{1,0}));
    require(session.poll().empty() && polls == 0,"load_signal_enabled_poll");
    require(session.feed(message(Bytes{0,0})).size() == 2,"map_ready_output");
    const auto output = session.poll();
    require(polls == 1 && output.size() == 1 && plain_response(output[0]) == turn,"poll_output_not_encoded");
    const auto action = session.feed(message(Bytes{3,0,1,0,0x81,0x92}));
    require(action.size() == 2 && counts.actions == 1,"poll_did_not_advance_context");
    session.finish(); session.finish();
    require(session.poll().empty() && polls == 1 && counts.released == 1,"poll_after_close_or_duplicate_release");
}

void invalid_poll_output_and_throw_release_once() {
    const std::vector<std::pair<Bytes,const char*>> failures{
        {{0,0x40,0x56,0x34},"original_game_duplicate_initialization"},
        {{0x11,0x40,0x57,0x34},"original_game_response_instance_mismatch"},
        {{0x10,0x40,0x56,0x34,0,0},"original_game_turn_truncated"},
        {{0x10,0x40,0x56,0x34,1,0,0},"original_game_turn_slot_invalid"},
        {{4,0x40,0x56,0x34,1,0,0,0,3,0,0,0},"original_game_snapshot_truncated"}
    };
    for (const auto& [response,code] : failures) {
        Counts counts;
        {
            auto strategy = plan(counts);
            strategy.poll = [response] { return std::vector<Bytes>{response}; };
            GameSession session(ClientVersion::legacy,direct_callbacks(std::move(strategy)));
            session.feed(ticket(direct_admission())); session.feed(message(Bytes{0,0}));
            rejects([&] { session.poll(); },code);
            require(session.state() == GameState::closed && counts.released == 1,"invalid_poll_not_closed_and_released");
            session.finish(); session.finish();
        }
        require(counts.released == 1,"invalid_poll_release_repeated");
    }
    Counts counts;
    {
        auto strategy = plan(counts);
        strategy.poll = []() -> std::vector<Bytes> { throw CodecError("poll_fixture_failure"); };
        strategy.disconnected = [&] { ++counts.released; throw CodecError("cleanup_fixture_failure"); };
        GameSession session(ClientVersion::legacy,direct_callbacks(std::move(strategy)));
        session.feed(ticket(direct_admission())); session.feed(message(Bytes{0,0}));
        rejects([&] { session.poll(); },"poll_fixture_failure");
        require(counts.released == 1,"throwing_poll_cleanup_missing");
        session.finish();
    }
    require(counts.released == 1,"throwing_poll_cleanup_repeated");
}

void session_destruction_releases_admission_and_poll_encoding_errors() {
    int releases = 0;
    auto callbacks = GameCallbacks{};
    callbacks.authorize_admission = [](const GameAdmission&) { return true; };
    callbacks.disconnected = [&](const GameAdmission&) { ++releases; throw CodecError("raw_cleanup_failure"); };
    callbacks.poll = [](const GameAdmission&) { return std::vector<Frame>{{299,Bytes(max_frame_total,0x19)}}; };
    {
        GameSession session(ClientVersion::legacy,callbacks);
        session.feed(ticket(direct_admission()));
    }
    require(releases == 1,"destructor_missing_cleanup");
    {
        GameSession session(ClientVersion::legacy,callbacks,[](const std::string& line) {
            if (line == "game_disconnect_callback_failed") throw CodecError("log_fixture_failure");
        });
        session.feed(ticket(direct_admission()));
        rejects([&] { session.poll(); },"frame_exceeds_local_limit");
        require(releases == 2 && session.poll().empty(),"poll_encode_failure_cleanup");
        session.finish();
    }
    require(releases == 2,"encode_failure_released_twice");
    {
        GameSession session(ClientVersion::legacy,callbacks);
        session.feed(ticket(direct_admission())); session.feed(Bytes{0x2b,1,0});
        rejects([&] { session.finish(); },"truncated_stream");
        require(releases == 3,"truncated_stream_cleanup_missing");
        session.finish();
    }
    require(releases == 3,"truncated_stream_cleanup_repeated");
}

void optional_poll_keeps_existing_strategy_unchanged() {
    Counts counts;
    GameSession session(ClientVersion::legacy,direct_callbacks(plan(counts)));
    session.feed(ticket(direct_admission())); session.feed(message(Bytes{0,0}));
    require(session.poll().empty(),"missing_poll_generated_packets");
    require(session.feed(message(Bytes{3,0,0,0})).size() == 2,"optional_poll_changed_context");
    session.finish();
}

void tcp_idle_poll_failure_isolation_eof_and_stop() {
    std::array<Counts,3> counts;
    std::array<std::atomic_int,3> gates{};
    std::array<std::atomic_int,3> polls{};
    std::mutex mutex;
    std::condition_variable changed;
    Running running([&] {
        return make_original_game_callbacks([&](const GameAdmission& admission) -> std::optional<OriginalGamePlan> {
            require(admission.id2 >= 25 && admission.id2 <= 27,"fixture_identity_out_of_range");
            const auto index = static_cast<std::size_t>(admission.id2-25);
            auto strategy = plan(counts[index],static_cast<std::int16_t>(admission.id2));
            strategy.poll = [&,index] {
                ++polls[index];
                const auto gate = gates[index].exchange(0);
                if (gate == 2) throw CodecError("tcp_poll_fixture_failure");
                return gate == 1 ? std::vector<Bytes>{turn} : std::vector<Bytes>{};
            };
            strategy.disconnected = [&,index] {
                const std::lock_guard lock(mutex); ++counts[index].released; changed.notify_all();
            };
            return strategy;
        });
    });
    const auto port = running.service.bound_port();
    const Client first(port),failed(port),waiting(port);
    auto admission = direct_admission();
    first.send(ticket(admission)); ++admission.id2; failed.send(ticket(admission));
    ++admission.id2; waiting.send(ticket(admission));
    require(first.plain() == expected_init(25) && failed.plain() == expected_init(26) &&
            waiting.plain() == expected_init(27),"tcp_poll_admission_failed");
    first.send(message(Bytes{0,0})); failed.send(message(Bytes{0,0}));
    require(first.plain() == expected_snapshot() && first.plain() == turn &&
            failed.plain() == expected_snapshot() && failed.plain() == turn,"tcp_map_ready_failed");
    gates[0].store(1);
    require(first.plain() == turn,"idle_poll_not_delivered");
    gates[1].store(2); failed.closed();
    require(counts[1].released == 1,"poll_failure_not_released");
    gates[0].store(1);
    require(first.plain() == turn,"poll_failure_affected_other_peer");
    require(polls[2] == 0,"unready_tcp_peer_polled");
    first.send(message(Bytes{3,0,2,0,0x81,0x92}));
    require(first.plain() == opaque_result && first.plain() == turn,"idle_poll_context_not_used_by_action");
    require(shutdown(first.socket,SD_SEND) == 0,"eof_shutdown_failed"); first.closed();
    {
        std::unique_lock lock(mutex);
        require(changed.wait_for(lock,std::chrono::seconds(2),[&] { return counts[0].released == 1; }),"eof_not_released");
    }
    running.finish(); waiting.closed();
    require(counts[0].released == 1 && counts[1].released == 1 && counts[2].released == 1,"stop_cleanup_missing_or_duplicated");
    require(running.service.bound_port() == 0,"stop_left_listener_bound");
}
}
static_assert(!std::is_copy_constructible_v<richnet::GameSession>);
int main() {
    try {
        const Network network;
        poll_waits_for_map_ready_and_advances_action_context();
        invalid_poll_output_and_throw_release_once();
        session_destruction_releases_admission_and_poll_encoding_errors();
        optional_poll_keeps_existing_strategy_unchanged();
        tcp_idle_poll_failure_isolation_eof_and_stop();
        std::cout << "PASS original game idle polling, map gate, context, failure isolation and cleanup.\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
