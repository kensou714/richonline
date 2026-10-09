#include "original_handoff_tcp_support.hpp"
#include <iostream>

namespace {
using namespace original_handoff_test;
struct Evidence {
    std::atomic_uint calls{0}, released{0}, ready{0}, actions{0};
    std::atomic_bool invalid_plan{false};
};
OriginalRoomGameProvider provider(Evidence& evidence) {
    return [&evidence](const OriginalRoomSnapshot& room) {
        ++evidence.calls;
        check(room.channel_id == 3 && room.players.size() == 1 && room.players[0].slot == 0 &&
            room.owner == room.players[0].user_id && room.players[0].profile.size() == 268 &&
            room.description.map_name == "BS_1_1.emp","handoff_provider_snapshot_wrong");
        const auto user = room.players[0].user_id;
        check(user <= 32767,"handoff_fixture_user_out_of_range");
        OriginalGamePlan plan{game::startup(static_cast<std::int16_t>(user)),
            [&evidence] { ++evidence.ready; return std::vector<Bytes>{game::turn}; },
            [&evidence](View) { ++evidence.actions; return std::vector<Bytes>{}; },
            [&evidence] { ++evidence.released; }};
        if (evidence.invalid_plan.load()) plan.action = {};
        return std::vector<OriginalGamePlanForUser>{{user,std::move(plan)}};
    };
}
void game_enter(const game::Client& client, const GameAdmission& admission) {
    client.send(game::ticket(admission));
    auto expected = game::expected_init();
    expected[20] = static_cast<std::uint8_t>(admission.id2);
    expected[21] = static_cast<std::uint8_t>(admission.id2 >> 8);
    check(client.plain() == expected,"handoff_game_initialization_wrong");
    client.send(game::message(Bytes{0,0}));
    check(client.plain() == game::expected_snapshot() && client.plain() == game::turn,"handoff_game_map_ready_wrong");
}
Json account(Storage& storage, std::string_view name) {
    return storage.dispatch("accounts.create",{{"username",name},{"password","handoff-password"}}).at("account");
}
const ControlLog log = [](const std::string& event,const Json& details) {
    if (event == "listener_failed") std::cerr << event << ' ' << details.dump() << '\n';
};
void success_replay_reuse_and_shutdown(const Scratch& scratch) {
    Storage storage(scratch.path/L"success.sqlite3",ClientProfile::original);
    const auto user = account(storage,"HandoffOwner");
    const auto id = user.at("role_id").get<std::uint32_t>();
    Evidence evidence;
    LobbyRuntime runtime(storage,scratch.path/L"bootstrap.json",log,{},
        OriginalRuntimeGame{0,{127,0,0,1},std::chrono::seconds(5),provider(evidence)});
    const auto state = runtime.status();
    check(state.at("lobbyReady") == true && state.at("gameListenerReady") == true,"handoff_listeners_not_ready");
    const auto port = state.at("gamePort").get<std::uint16_t>();
    Socket lobby(state.at("lobbyPort").get<std::uint16_t>()); login(lobby,user);
    const auto room = create(lobby);
    const auto first = ready(lobby,room,id,port);
    {
        auto invalid = first; invalid.opaque8[0] ^= 0x80;
        const game::Client wrong(port); wrong.send(game::ticket(invalid)); wrong.closed();
        check(evidence.released.load() == 0 && evidence.ready.load() == 0,"handoff_bad_ticket_consumed_reservation");
    }
    {
        const game::Client playing(port); game_enter(playing,first);
        const game::Client replay(port); replay.send(game::ticket(first)); replay.closed();
        check(evidence.ready.load() == 1 && evidence.released.load() == 0,"handoff_replayed_ticket_disturbed_game");
        playing.send(game::message(Bytes{10,0})); playing.closed();
        departed(lobby,room,id);
        check(evidence.released.load() == 1,"handoff_leave_cleanup_not_once");
    }
    const auto reused = create(lobby);
    check(reused == room,"handoff_room_id_not_reused");
    const auto second = ready(lobby,reused,id,port);
    check(second != first,"handoff_room_reuse_kept_old_ticket");
    {
        const game::Client stale(port); stale.send(game::ticket(first)); stale.closed();
        const game::Client playing(port); game_enter(playing,second);
        playing.send(game::message(Bytes{10,0})); playing.closed(); departed(lobby,reused,id);
    }
    check(evidence.calls.load() == 2 && evidence.ready.load() == 2 && evidence.released.load() == 2,
        "handoff_reused_game_lifecycle_wrong");
    const auto stop_room = create(lobby);
    const auto stopped_ticket = ready(lobby,stop_room,id,port);
    const game::Client active(port); game_enter(active,stopped_ticket);
    runtime.stop(); runtime.stop(); active.closed();
    check(evidence.released.load() == 3 && evidence.calls.load() == 3 && evidence.actions.load() == 0,
        "handoff_shutdown_cleanup_not_once");
    const auto stopped = runtime.status();
    check(stopped.at("lobbyReady") == false && stopped.at("gameListenerReady") == false &&
        stopped.at("lobbyPort") == 0 && stopped.at("gamePort") == 0,"handoff_shutdown_left_listeners");
}
void idle_expiry_keeps_room(const Scratch& scratch) {
    Storage storage(scratch.path/L"expiry.sqlite3",ClientProfile::original);
    const auto user = account(storage,"HandoffExpiry"); const auto id = user.at("role_id").get<std::uint32_t>();
    Evidence evidence;
    LobbyRuntime runtime(storage,scratch.path/L"bootstrap.json",log,{},
        OriginalRuntimeGame{0,{127,0,0,1},std::chrono::milliseconds(1000),provider(evidence)});
    const auto state = runtime.status(); const auto port = state.at("gamePort").get<std::uint16_t>();
    Socket lobby(state.at("lobbyPort").get<std::uint16_t>()); login(lobby,user);
    const auto room = create(lobby); const auto expired = ready(lobby,room,id,port);
    configuration(lobby,room,false);
    const auto cancel = lobby.receive();
    check(cancel.wire_type == 96 && cancel.payload == words({id,room}),"handoff_idle_expiry_did_not_cancel_ready");
    check(evidence.released.load() == 1 && evidence.ready.load() == 0,"handoff_idle_expiry_cleanup_wrong");
    const auto replacement = ready(lobby,room,id,port);
    const game::Client stale(port); stale.send(game::ticket(expired)); stale.closed();
    const game::Client playing(port); game_enter(playing,replacement);
    playing.send(game::message(Bytes{10,0})); playing.closed(); departed(lobby,room,id);
    runtime.stop();
    check(evidence.calls.load() == 2 && evidence.released.load() == 2 && evidence.ready.load() == 1,"handoff_expiry_restart_wrong");
}
void unavailable_and_failed_provider_roll_back(const Scratch& scratch) {
    Storage storage(scratch.path/L"failure.sqlite3",ClientProfile::original);
    const auto user = account(storage,"HandoffFailure"); const auto id = user.at("role_id").get<std::uint32_t>();
    Evidence evidence;
    for (const auto with_host : {false,true}) {
        std::optional<OriginalRuntimeGame> options;
        evidence.invalid_plan.store(true);
        if (with_host) options = OriginalRuntimeGame{0,{127,0,0,1},std::chrono::seconds(5),provider(evidence)};
        LobbyRuntime runtime(storage,scratch.path/L"bootstrap.json",log,{},options);
        Socket lobby(runtime.status().at("lobbyPort").get<std::uint16_t>()); login(lobby,user);
        const auto room = create(lobby); lobby.send({5,{}});
        const auto prepared = lobby.receive(), cancelled = lobby.receive();
        check(prepared.wire_type == 13 && prepared.payload == words({id,room}) &&
            cancelled.wire_type == 96 && cancelled.payload == words({id,room}),"handoff_provider_failure_did_not_rollback");
        lobby.send({6,words({0})}); departed(lobby,room,id);
        check(create(lobby) == room,"handoff_provider_failure_left_room_locked");
        runtime.stop();
    }
    check(evidence.calls.load() == 1 && evidence.released.load() == 1,"handoff_failed_provider_cleanup_wrong");
}
}
int main() {
    try {
        const original_runtime_test::Network network;
        const Scratch scratch; bootstrap(scratch.path/L"bootstrap.json");
        success_replay_reuse_and_shutdown(scratch); idle_expiry_keeps_room(scratch); unavailable_and_failed_provider_roll_back(scratch);
        std::cout << "PASS original lobby/game TCP handoff, ticket isolation, room reuse, idle expiry and cleanup; fixture gameplay only.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
