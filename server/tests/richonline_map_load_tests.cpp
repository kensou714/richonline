#include "richonline_game_registry.hpp"
#include "richonline_game_startup.hpp"
#include "richonline_terminal_coordinator.hpp"

#include <windows.h>
#include <sqlite3.h>

#include <chrono>
#include <iostream>
#include <limits>
#include <string_view>

namespace {
using namespace richnet;
using Clock = RichonlineMapLoadPolicy::Clock;
using namespace std::chrono_literals;

void check(bool value, std::string_view reason) {
    if (!value) throw std::runtime_error(std::string(reason));
}
template<class F> void rejects(F action, std::string_view code) {
    try { action(); }
    catch (const CodecError& error) { check(error.what() == code, "wrong_rejection"); return; }
    throw std::runtime_error("missing_rejection");
}
const GameAdmission identity{7,19,25,{1,2,3,4,5,6,7,8},0x8b7a6910,{}};
Bytes filler(std::size_t size) { return Bytes(size,0x81); }
Bytes incoming(const Bytes& plain) {
    return encode_frame(richonline_board_frame(plain,{0,-1},filler(plain.size()+2)),
        {Channel::game_c2s,{},ClientVersion::richonline});
}
std::vector<Bytes> admit(GameSession& session, const GameAdmission& admission = identity) {
    return session.feed(encode_frame(encode_game_admission(admission,ClientVersion::richonline),
        {Channel::game_c2s,{},ClientVersion::richonline}));
}
RichonlineStartupPlan plan(int& ready, int& actions, int& disconnected) {
    return {
        {0x1234,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
            {{25,1,2,{1,2,3,4,5,6,7,8,9,10},0xb1},{-1,9,3,{11,12,13,14,15,16,17,18,19,20},0xb2}}},
        {0x1234,0x88774433,100,{{2000,3000,4},{5000,6000,7}}}, {9,-3},
        [&] { ++ready; return std::vector<Bytes>{}; },
        [&](const Envelope299&,View) { ++actions; return std::vector<Bytes>{}; },
        [&] { ++disconnected; }
    };
}
void policy_is_strict_and_authorization_does_not_start_the_clock() {
    for (const auto timeout : {-1ms,0ms,999ms,600001ms}) {
        int ready=0,actions=0,disconnected=0,clock_reads=0;
        auto callbacks=make_richonline_game_callbacks([&](const GameAdmission&) -> std::optional<RichonlineStartupPlan> {
            auto value=plan(ready,actions,disconnected);
            value.map_loading=RichonlineMapLoadPolicy{timeout,[&] { ++clock_reads; return Clock::time_point{}; }};
            return value;
        },filler);
        rejects([&] { callbacks.authorize_admission(identity); },"richonline_map_load_policy_invalid");
        check(disconnected==1 && clock_reads==0 && ready==0 && actions==0,"invalid_policy_kept_resources_or_read_clock");
    }
    {
        int ready=0,actions=0,disconnected=0;
        auto callbacks=make_richonline_game_callbacks([&](const GameAdmission&) -> std::optional<RichonlineStartupPlan> {
            auto value=plan(ready,actions,disconnected);
            value.map_loading=RichonlineMapLoadPolicy{1000ms,{}};
            return value;
        },filler);
        rejects([&] { callbacks.authorize_admission(identity); },"richonline_map_load_policy_invalid");
        check(disconnected==1,"absent_clock_kept_resources");
    }
    for (const auto timeout : {1000ms,600000ms}) {
        auto now=Clock::time_point{};
        int ready=0,actions=0,disconnected=0,clock_reads=0;
        auto callbacks=make_richonline_game_callbacks([&](const GameAdmission&) -> std::optional<RichonlineStartupPlan> {
            auto value=plan(ready,actions,disconnected);
            value.map_loading=RichonlineMapLoadPolicy{timeout,[&] { ++clock_reads; return now; }};
            return value;
        },filler);
        check(callbacks.authorize_admission(identity) && clock_reads==0,"authorization_started_loading_limit");
        now+=24h;
        check(callbacks.poll(identity).empty() && clock_reads==0,"prepared_plan_started_loading_limit");
        check(callbacks.admitted(identity).size()==2 && clock_reads==1,"actual_admission_did_not_start_loading_limit");
        now+=timeout-1ms;
        check(callbacks.poll(identity).empty() && clock_reads==2,"timeout_boundary_fired_early");
        check(callbacks.admitted(identity).size()==2 && clock_reads==2,"duplicate_admitted_restarted_deadline");
        now+=1ms;
        rejects([&] { callbacks.poll(identity); },"richonline_map_load_timeout");
        callbacks.disconnected(identity);
        const auto reads_after_release=clock_reads;
        check(callbacks.poll(identity).empty() && clock_reads==reads_after_release && disconnected==1,
            "released_plan_retained_loading_deadline");
    }
}
void game_session_timeout_closes_once_and_init_ack_does_not_extend_it() {
    auto now=Clock::time_point{};
    int ready=0,actions=0,disconnected=0,polls=0;
    GameSession session(ClientVersion::richonline,make_richonline_game_callbacks(
        [&](const GameAdmission&) -> std::optional<RichonlineStartupPlan> {
            auto value=plan(ready,actions,disconnected);
            value.map_loading=RichonlineMapLoadPolicy{1000ms,[&] { return now; }};
            value.poll=[&] { ++polls; return std::vector<Bytes>{}; };
            return value;
        },filler));
    check(admit(session).size()==2,"admission_output_changed");
    now+=999ms;
    check(session.feed(incoming({1,0})).empty() && session.poll().empty(),"init_ack_started_game_or_timed_out_early");
    now+=1ms;
    check(session.feed(incoming({1,0})).empty(),"second_init_ack_changed_state");
    rejects([&] { session.poll(); },"richonline_map_load_timeout");
    check(session.state()==GameState::closed && disconnected==1 && ready==0 && actions==0 && polls==0,
        "map_timeout_did_not_close_and_release_once");
    check(session.poll().empty(),"closed_session_polled_loading_deadline");
    session.finish();
    check(disconnected==1,"map_timeout_repeated_cleanup");
}
void ready_success_clears_only_the_startup_limit_and_preserves_transport_hooks() {
    auto now=Clock::time_point{};
    int ready=0,actions=0,disconnected=0,polls=0,clock_reads=0,sends=0;
    GameSession session(ClientVersion::richonline,make_richonline_game_callbacks(
        [&](const GameAdmission&) -> std::optional<RichonlineStartupPlan> {
            auto value=plan(ready,actions,disconnected);
            value.map_loading=RichonlineMapLoadPolicy{1000ms,[&] { ++clock_reads; return now; }};
            value.poll=[&] { ++polls; return std::vector<Bytes>{}; };
            value.sent=[&](View plain) {
                check(plain.size()>=2,"sent_plain_truncated");
                const auto opcode=read_le(plain.first(2));
                check(opcode==0x4000 || opcode==0x4004,"startup_sent_hook_changed");
                ++sends;
            };
            return value;
        },filler));
    for (const auto& response : admit(session)) session.sent(response);
    now+=1000ms;
    // Expiration is checked by poll. A valid ready0 processed first wins this boundary.
    for (const auto& response : session.feed(incoming({0,0}))) session.sent(response);
    check(ready==1 && clock_reads==1 && sends==2,"ready0_or_transport_hook_failed");
    now+=30*24h;
    check(session.poll().empty() && polls==1 && clock_reads==1,"map_limit_became_total_game_timeout");
    check(session.feed(incoming({0,0})).empty() && ready==1 && clock_reads==1,"duplicate_ready_restarted_loading");
    check(session.poll().empty() && polls==2 && session.state()==GameState::admitted,"long_running_ready_game_closed");
    session.finish();
    check(disconnected==1,"ready_game_cleanup_changed");
}
void malformed_or_failed_ready_never_clears_the_loading_limit() {
    for (const bool invalid_output : {false,true}) {
        auto now=Clock::time_point{};
        int ready=0,actions=0,disconnected=0;
        auto callbacks=make_richonline_game_callbacks([&](const GameAdmission&) -> std::optional<RichonlineStartupPlan> {
            auto value=plan(ready,actions,disconnected);
            value.map_loading=RichonlineMapLoadPolicy{1000ms,[&] { return now; }};
            if (invalid_output) value.map_ready=[&] { ++ready; return std::vector<Bytes>{{0x10,0x40,0x78,0x56,0,0,0}}; };
            return value;
        },filler);
        check(callbacks.authorize_admission(identity),"ready_failure_authorization_rejected");
        callbacks.admitted(identity);
        const auto plain=invalid_output ? Bytes{0,0} : Bytes{0,0,1};
        rejects([&] { callbacks.message(identity,{},plain); },invalid_output ?
            "richonline_game_response_instance_mismatch" : "richonline_game_signal_length_invalid");
        check(ready==(invalid_output ? 1 : 0),"malformed_ready_entered_strategy");
        now+=1000ms;
        rejects([&] { callbacks.poll(identity); },"richonline_map_load_timeout");
        callbacks.disconnected(identity);
        check(disconnected==1 && actions==0,"ready_failure_cleanup_changed");
    }
    int ready=0,actions=0,disconnected=0;
    GameSession session(ClientVersion::richonline,make_richonline_game_callbacks(
        [&](const GameAdmission&) -> std::optional<RichonlineStartupPlan> {
            auto value=plan(ready,actions,disconnected);
            value.map_loading=RichonlineMapLoadPolicy{1000ms,Clock::now};
            return value;
        },filler));
    admit(session);
    rejects([&] { session.feed(incoming({0,0,1})); },"richonline_game_signal_length_invalid");
    check(session.state()==GameState::closed && disconnected==1 && ready==0,"malformed_ready_counted_as_loaded");
}
void optional_policy_preserves_existing_startup() {
    int ready=0,actions=0,disconnected=0;
    GameSession session(ClientVersion::richonline,make_richonline_game_callbacks(
        [&](const GameAdmission&) -> std::optional<RichonlineStartupPlan> { return plan(ready,actions,disconnected); },filler));
    admit(session);
    for (int i=0;i<5;++i) check(session.poll().empty(),"absent_loading_policy_created_timeout");
    check(session.state()==GameState::admitted && ready==0,"optional_policy_started_game");
    check(session.feed(incoming({0,0})).size()==1 && ready==1,"optional_policy_changed_ready");
    session.finish();
    check(disconnected==1,"optional_policy_changed_cleanup");
}

class Database {
public:
    explicit Database(const std::filesystem::path& path) {
        const auto name=path.u8string();
        check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db_)==SQLITE_OK,"fixture_open");
    }
    ~Database() { sqlite3_close(db_); }
    void exec(const char* statement) {
        check(sqlite3_exec(db_,statement,nullptr,nullptr,nullptr)==SQLITE_OK,"fixture_exec");
    }
    std::int64_t scalar(const char* sql) {
        sqlite3_stmt* statement=nullptr;
        check(sqlite3_prepare_v2(db_,sql,-1,&statement,nullptr)==SQLITE_OK,"fixture_prepare");
        check(sqlite3_step(statement)==SQLITE_ROW,"fixture_step");
        const auto result=sqlite3_column_int64(statement,0);
        sqlite3_finalize(statement);
        return result;
    }
private:
    sqlite3* db_{};
};
RichonlineTerminalContext terminal_context(std::int64_t actor, const std::string& match) {
    std::array<std::uint32_t,21> levels{};
    for (std::size_t i=0;i<levels.size();++i) levels[i]=static_cast<std::uint32_t>(i)*50;
    return {"map-loader",actor,0x1234,3,
        {match+":settlement",match,"fixture-map",GameOutcome::loss,10,{},
            {"isolated map loading refund fixture",{10,30,0},{5,18,0},{0,0,0},{0,0,0},levels,10}},
        {3,0,{1},{}},{"isolated fixture terminal rules",RichonlineSimultaneousDefeat::human_loss,0,1,1,0x63,false},
        "isolated fixture result byte; not production protocol evidence"};
}
void poll_timeout_refunds_sqlite_pledge_and_original_lobby_connection_can_prepare_again() {
    const auto path=std::filesystem::temp_directory_path()/("richonline-map-load-"+
        std::to_string(GetCurrentProcessId())+"-"+
        std::to_string(Clock::now().time_since_epoch().count())+".sqlite3");
    Storage storage(path);
    const auto actor=storage.dispatch("accounts.create",{{"username","map-loader"},{"password","isolated"}})
        .at("account").at("role_id").get<std::int64_t>();
    check(actor>0 && actor<=std::numeric_limits<std::int16_t>::max(),"fixture_role_range");
    Database db(path);
    db.exec("UPDATE roles SET gold=100,level=0,experience=0,wins=0,losses=0,draws=0");
    const auto gold=[&] { return storage.game_account_for_role(actor).gold; };
    auto now=Clock::time_point{};
    int prepared=0,ready=0,actions=0,disconnected=0,refunds=0;
    std::vector<GameAdmission> descriptors;
    std::vector<std::shared_ptr<RichonlineTerminalCoordinator>> flows;
    RichonlineRoomSnapshot room{3,static_cast<std::uint32_t>(actor),{},
        {{777,static_cast<std::uint32_t>(actor),0,true}},9};
    room.description.extension=Bytes(88,0xa5);
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& snapshot) {
        check(snapshot.participants.size()==1 && snapshot.participants.front().connection==777,"original_lobby_binding_changed");
        ++prepared;
        const auto flow=std::make_shared<RichonlineTerminalCoordinator>(storage,
            terminal_context(actor,"map-load-match-"+std::to_string(prepared)));
        check(flow->prepare_start()->gold_after==90,"entry_pledge_not_reserved");
        flows.push_back(flow);
        const RichonlineGameRedirect redirect{{127,0,0,1},18602,0x11223344,
            {static_cast<std::uint8_t>(prepared),2,3,4,5,6,7,8}};
        const auto descriptor=richonline_expected_admission({9,snapshot.key,static_cast<std::uint32_t>(actor)},redirect);
        descriptors.push_back(descriptor);
        auto callbacks=make_richonline_game_callbacks([&,flow](const GameAdmission&) -> std::optional<RichonlineStartupPlan> {
            auto value=plan(ready,actions,disconnected);
            value.init.participants[0].lobby_identity=static_cast<std::int16_t>(actor);
            value.map_loading=RichonlineMapLoadPolicy{1000ms,[&] { return now; }};
            value.map_ready=[&,flow] { ++ready; flow->activate(); return std::vector<Bytes>{}; };
            value.disconnected=[&,flow] {
                ++disconnected;
                const auto result=flow->abandon("game transport ended before map ready0");
                check(result.action==RichonlineTerminalAbandonAction::startup_refunded && result.startup_refund &&
                    result.startup_refund->gold_after==100,"existing_startup_abandon_did_not_refund");
                ++refunds;
            };
            return value;
        },filler);
        // Preparation validates and reserves the plan, independently of its actual game admission.
        check(callbacks.authorize_admission(descriptor),"prepared_startup_not_authorized");
        return std::vector<RichonlineGamePlan>{{777,static_cast<std::uint32_t>(actor),redirect,
            [callbacks,descriptor] { return callbacks.admitted(descriptor); },
            [callbacks,descriptor](const Envelope299& envelope,View plain) { return callbacks.message(descriptor,envelope,plain); },
            [callbacks,descriptor] { callbacks.disconnected(descriptor); },
            [callbacks,descriptor] { return callbacks.poll(descriptor); }}};
    },9,30s,[&] { return now; });
    check(registry.prepare(room).size()==1 && gold()==90,"first_game_not_prepared");
    now+=29s;
    GameSession first(ClientVersion::richonline,registry.callbacks());
    check(admit(first,descriptors.front()).size()==2,"prepared_age_incorrectly_expired_map_load");
    now+=999ms;
    check(first.poll().empty() && gold()==90,"loading_timeout_fired_early_or_refunded_active_hold");
    now+=1ms;
    rejects([&] { first.poll(); },"richonline_map_load_timeout");
    check(first.state()==GameState::closed && gold()==100 && disconnected==1 && refunds==1 && ready==0 && actions==0,
        "poll_timeout_did_not_run_existing_disconnect_refund_path");
    check(!registry.has_room(9,3) && db.scalar("SELECT count(*) FROM game_entry_pledges WHERE state='held'")==0 &&
        db.scalar("SELECT count(*) FROM game_entry_pledges WHERE state='refunded'")==1 &&
        db.scalar("SELECT count(*) FROM operations WHERE source='native-game-pledge-refund'")==1 &&
        db.scalar("SELECT count(*) FROM operations WHERE source='native-game-settlement'")==0,
        "timed_out_game_left_hold_or_fabricated_loss");
    first.finish();
    check(gold()==100 && refunds==1,"finished_timeout_duplicate_refund");
    check(registry.prepare(room).size()==1 && prepared==2 && gold()==90,"same_lobby_connection_cannot_prepare_next_game");
    GameSession second(ClientVersion::richonline,registry.callbacks());
    check(admit(second,descriptors.back()).size()==2 && second.state()==GameState::admitted,"same_lobby_connection_next_admission_failed");
    second.finish();
    check(gold()==100 && disconnected==2 && refunds==2 && !registry.has_room(9,3) &&
        db.scalar("SELECT count(*) FROM game_entry_pledges WHERE state='refunded'")==2,"second_startup_cleanup_not_refunded");
    check(flows.front()->phase()==RichonlineTerminalPhase::aborted && flows.back()->phase()==RichonlineTerminalPhase::aborted,
        "coordinator_loading_abort_phase_wrong");
    registry.shutdown();
}
}
int main() {
    try {
        policy_is_strict_and_authorization_does_not_start_the_clock();
        game_session_timeout_closes_once_and_init_ack_does_not_extend_it();
        ready_success_clears_only_the_startup_limit_and_preserves_transport_hooks();
        malformed_or_failed_ready_never_clears_the_loading_limit();
        optional_policy_preserves_existing_startup();
        poll_timeout_refunds_sqlite_pledge_and_original_lobby_connection_can_prepare_again();
        std::cout << "PASS map ready0 deadline boundaries, whole sends, SQLite refund and same lobby next admission\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
