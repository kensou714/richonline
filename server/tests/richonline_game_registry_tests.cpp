#include "richonline_game_registry.hpp"
#include "service.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <atomic>
#include <future>
#include <latch>
#include <condition_variable>
#include <string_view>
#include <thread>

namespace {
using namespace richnet;
void require(bool condition, const char* code) { if (!condition) throw CodecError(code); }
template<class F> void rejects(F action, std::string_view code) {
    try { action(); } catch (const CodecError& error) { require(error.what() == code, "wrong_error"); return; }
    throw CodecError("rejection_missing");
}
RichonlineRoomSnapshot room() {
    RichonlineRoomSnapshot result{3, 11, {}, {{1,11,0,true},{2,22,1,true}},9};
    result.description.extension = Bytes(88, 0xa5);
    return result;
}
RichonlineGameRedirect redirect(std::uint8_t tag) { return {{127,0,0,1}, 18602, 0x11223344, {tag,2,3,4,5,6,7,8}}; }
RichonlineGamePlan plan(const RichonlineRoomPeer& peer, int& disconnected) {
    return {peer.connection, peer.actor, redirect(static_cast<std::uint8_t>(peer.connection)),
        [] { return std::vector<Frame>{{299, {1,2}}}; },
        [](const Envelope299&, View) { return std::vector<Frame>{{299, {3,4}}}; },
        [&disconnected] { ++disconnected; }};
}
void all_members_register_before_redirect_and_echo_is_once_only() {
    auto now = AdmissionClock::time_point{};
    int disconnected = 0;
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& snapshot) {
        std::vector<RichonlineGamePlan> plans;
        for (const auto& peer : snapshot.participants) plans.push_back(plan(peer, disconnected));
        return plans;
    }, 9, std::chrono::seconds(30), [&] { return now; });
    const auto redirects = registry.prepare(room());
    require(redirects.size() == 2 && redirects[0].frame.wire_type == 22 && redirects[0].frame.payload.size() == 18,
            "redirects_missing");
    auto a = registry.callbacks(); auto replay = registry.callbacks();
    const auto descriptor = richonline_expected_admission({9,3,11}, redirect(1));
    auto wrong = richonline_expected_admission({9,4,11}, redirect(1));
    require(!a.authorize_admission(wrong), "cross_room_admission_accepted");
    require(a.authorize_admission(descriptor), "valid_admission_rejected");
    require(!replay.authorize_admission(descriptor), "admission_replay_accepted");
    require(a.admitted(descriptor).size() == 1, "startup_missing");
    now += std::chrono::minutes(2);
    require(a.message(descriptor, {}, {}).size() == 1, "active_game_expired_with_pending_ttl");
    auto expired = registry.callbacks();
    require(!expired.authorize_admission(richonline_expected_admission({9,3,22}, redirect(2))), "pending_admission_did_not_expire");
    registry.cancel_room(3);
    rejects([&] { a.message(descriptor, {}, {}); }, "richonline_game_plan_cancelled");
    a.disconnected(descriptor);
    require(disconnected == 2, "plan_cleanup_count_wrong");
}
void partial_provider_failure_creates_no_admission() {
    int disconnected = 0;
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& snapshot) {
        return std::vector<RichonlineGamePlan>{plan(snapshot.participants[0], disconnected)};
    }, 9, std::chrono::seconds(30));
    rejects([&] { registry.prepare(room()); }, "richonline_game_plan_membership_mismatch");
    require(disconnected == 1, "rejected_provider_plan_not_cleaned");
    auto callbacks = registry.callbacks();
    require(!callbacks.authorize_admission(richonline_expected_admission({9,3,11}, redirect(1))), "partial_plan_admission_leaked");
}
void pending_expiry_and_game_disconnect_cancel_the_whole_room() {
    auto now = AdmissionClock::time_point{};
    int disconnected = 0;
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& snapshot) {
        std::vector<RichonlineGamePlan> plans;
        for (const auto& peer : snapshot.participants) plans.push_back(plan(peer, disconnected));
        return plans;
    }, 9, std::chrono::seconds(30), [&] { return now; });
    static_cast<void>(registry.prepare(room()));
    require(registry.has_room(3), "prepared_room_missing");
    now += std::chrono::seconds(31);
    require(!registry.has_room(3) && disconnected == 2, "expired_room_not_cancelled");
    static_cast<void>(registry.prepare(room()));
    const auto descriptor = richonline_expected_admission({9,3,11}, redirect(1));
    auto callbacks = registry.callbacks();
    require(callbacks.authorize_admission(descriptor), "renewed_admission_rejected");
    callbacks.disconnected(descriptor);
    require(!registry.has_room(3) && disconnected == 4, "game_disconnect_left_pending_entries");
    auto other = registry.callbacks();
    require(!other.authorize_admission(richonline_expected_admission({9,3,22}, redirect(2))), "other_member_entered_cancelled_game");
}
void cancellation_waits_for_running_action_before_cleanup() {
    std::latch action_started(1), allow_finish(1);
    std::atomic_bool executing{false}, cleanup_overlap{false};
    std::atomic_int cleanup_count{0};
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& snapshot) {
        std::vector<RichonlineGamePlan> plans;
        for (const auto& peer : snapshot.participants) plans.push_back({peer.connection, peer.actor, redirect(static_cast<std::uint8_t>(peer.connection)),
            [] { return std::vector<Frame>{}; },
            [&](const Envelope299&, View) {
                executing.store(true); action_started.count_down(); allow_finish.wait(); executing.store(false);
                return std::vector<Frame>{};
            }, [&] { if (executing.load()) cleanup_overlap.store(true); ++cleanup_count; }});
        return plans;
    }, 9, std::chrono::seconds(30));
    static_cast<void>(registry.prepare(room()));
    auto callbacks = registry.callbacks();
    const auto descriptor = richonline_expected_admission({9,3,11}, redirect(1));
    require(callbacks.authorize_admission(descriptor), "concurrent_admission_failed");
    auto action = std::async(std::launch::async, [&] { callbacks.message(descriptor, {}, {}); });
    action_started.wait();
    auto cancelled = std::async(std::launch::async, [&] { registry.cancel_room(3); });
    const auto deadline = AdmissionClock::now() + std::chrono::seconds(5);
    while (registry.has_room(3) && AdmissionClock::now() < deadline) std::this_thread::yield();
    const bool invalidated = !registry.has_room(3);
    const bool waited = cancelled.wait_for(std::chrono::milliseconds(50)) == std::future_status::timeout;
    allow_finish.count_down();
    action.get(); cancelled.get();
    require(invalidated && waited && !cleanup_overlap && cleanup_count == 2, "cleanup_raced_running_game_action");
    registry.shutdown(); callbacks.disconnected(descriptor);
    require(cleanup_count == 2, "cleanup_called_twice");
}
void shutdown_cleans_unconsumed_plans_and_prevents_restart() {
    int cleaned = 0;
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& snapshot) {
        std::vector<RichonlineGamePlan> plans;
        for (const auto& peer : snapshot.participants) plans.push_back(plan(peer, cleaned));
        return plans;
    }, 9, std::chrono::seconds(30));
    static_cast<void>(registry.prepare(room()));
    registry.shutdown(); registry.shutdown();
    require(cleaned == 2 && !registry.has_room(3), "shutdown_plan_leak");
    rejects([&] { registry.prepare(room()); }, "richonline_game_registry_stopped");
}
void poll_requires_matching_admission_and_supports_an_absent_handler() {
    int cleaned = 0, polled = 0;
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& snapshot) {
        std::vector<RichonlineGamePlan> plans;
        for (const auto& peer : snapshot.participants) plans.push_back(plan(peer, cleaned));
        plans.front().poll = [&] { ++polled; return std::vector<Frame>{{299,{7,8,9}}}; };
        return plans;
    }, 9, std::chrono::seconds(30));
    static_cast<void>(registry.prepare(room()));
    auto callbacks = registry.callbacks();
    const auto descriptor = richonline_expected_admission({9,3,11}, redirect(1));
    require(static_cast<bool>(callbacks.poll), "registry_poll_missing");
    rejects([&] { callbacks.poll(descriptor); }, "richonline_game_plan_cancelled");
    require(callbacks.authorize_admission(descriptor), "poll_admission_failed");
    auto wrong = descriptor; ++wrong.id2;
    rejects([&] { callbacks.poll(wrong); }, "richonline_game_plan_cancelled");
    require(polled == 0, "unauthorized_poll_dispatched");
    const auto output = callbacks.poll(descriptor);
    require(polled == 1 && output.size() == 1 && output.front().wire_type == 299 &&
        output.front().payload == Bytes{7,8,9}, "poll_output_lost");
    auto other = registry.callbacks();
    const auto other_descriptor = richonline_expected_admission({9,3,22}, redirect(2));
    require(other.authorize_admission(other_descriptor), "empty_poll_admission_failed");
    require(other.poll(other_descriptor).empty(), "absent_poll_not_empty");
    registry.cancel_room(3);
    rejects([&] { callbacks.poll(descriptor); }, "richonline_game_plan_cancelled");
    rejects([&] { other.poll(other_descriptor); }, "richonline_game_plan_cancelled");
    require(polled == 1 && cleaned == 2, "cancelled_poll_executed");
}
void cancellation_waits_for_running_poll_before_cleanup() {
    std::latch poll_started(1), allow_finish(1);
    std::atomic_bool executing{false}, cleanup_overlap{false};
    std::atomic_int cleaned{0}, polled{0};
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& snapshot) {
        std::vector<RichonlineGamePlan> plans;
        for (const auto& peer : snapshot.participants) plans.push_back({peer.connection, peer.actor,
            redirect(static_cast<std::uint8_t>(peer.connection)), [] { return std::vector<Frame>{}; },
            [](const Envelope299&, View) { return std::vector<Frame>{}; },
            [&] { if (executing.load()) cleanup_overlap.store(true); ++cleaned; },
            [&] {
                ++polled; executing.store(true); poll_started.count_down(); allow_finish.wait(); executing.store(false);
                return std::vector<Frame>{};
            }});
        return plans;
    }, 9, std::chrono::seconds(30));
    static_cast<void>(registry.prepare(room()));
    auto callbacks = registry.callbacks();
    const auto descriptor = richonline_expected_admission({9,3,11}, redirect(1));
    require(callbacks.authorize_admission(descriptor), "concurrent_poll_admission_failed");
    auto poll = std::async(std::launch::async, [&] { callbacks.poll(descriptor); });
    poll_started.wait();
    auto cancelled = std::async(std::launch::async, [&] { registry.cancel_room(3); });
    const auto deadline = AdmissionClock::now() + std::chrono::seconds(5);
    while (registry.has_room(3) && AdmissionClock::now() < deadline) std::this_thread::yield();
    const bool invalidated = !registry.has_room(3);
    const bool waited = cancelled.wait_for(std::chrono::milliseconds(50)) == std::future_status::timeout;
    allow_finish.count_down();
    poll.get(); cancelled.get();
    require(invalidated && waited && !cleanup_overlap && cleaned == 2, "cleanup_raced_running_poll");
    rejects([&] { callbacks.poll(descriptor); }, "richonline_game_plan_cancelled");
    registry.shutdown(); callbacks.disconnected(descriptor);
    require(cleaned == 2 && polled == 1, "poll_or_cleanup_repeated_after_cancel");
}
void successful_sends_propagate_without_retiring_live_game() {
    int cleaned=0; std::array<bool,2> finished{}; std::array<int,2> confirmed{},lobby_confirmed{};
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& snapshot) {
        std::vector<RichonlineGamePlan> plans;
        for(const auto& peer:snapshot.participants) {
            auto value=plan(peer,cleaned); const auto index=static_cast<std::size_t>(peer.slot);
            value.sent=[&,index](const Frame& frame) { require(frame.wire_type==299,"registry_changed_sent_frame");++confirmed[index];finished[index]=true; };
            value.game_finished=[&,index] {return finished[index];};
            value.lobby_sent=[&,index](const Frame& frame) { require(frame.wire_type==58 && frame.payload==Bytes{0xa5},"registry_changed_lobby_sent_frame");++lobby_confirmed[index];finished[index]=false; };
            plans.push_back(std::move(value));
        }
        return plans;
    },9,std::chrono::seconds(30));
    registry.prepare(room());
    auto first=registry.callbacks(),second=registry.callbacks();
    const auto a=richonline_expected_admission({9,3,11},redirect(1));
    const auto b=richonline_expected_admission({9,3,22},redirect(2));
    require(!registry.completed_room(9,3) && !registry.notify_lobby_sent(1,{58,{0xa5}}),"unsent_game_exposed_lobby_completion");
    require(!first.sent_enabled(a),"unadmitted_plan_enabled_observer");
    rejects([&]{first.sent(a,{299,{}});},"richonline_game_plan_cancelled");
    require(first.authorize_admission(a) && second.authorize_admission(b),"sent_registry_admission_failed");
    require(first.sent_enabled(a) && second.sent_enabled(b),"observed_plan_disabled_send_tracking");
    auto wrong=a; ++wrong.id2;
    rejects([&]{first.sent(wrong,{299,{}});},"richonline_game_plan_cancelled");
    first.sent(a,{299,{1,2}});
    require(!registry.completed_room(9,3),"partly_sent_room_marked_completed");
    second.sent(b,{299,{3,4}});
    require(registry.completed_room(9,3) && registry.has_room(9,3) && !registry.completed_room(8,3),
        "completion_removed_live_game_or_lost_channel_dimension");
    require(first.message(a,{},{}).size()==1,"completed_game_no_longer_accepts_leave_handler");
    require(registry.notify_lobby_sent(1,{58,{0xa5}}) && registry.completed_room(9,3) && registry.has_room(9,3),
        "first_lobby_confirmation_retired_unconfirmed_members");
    require(!registry.notify_lobby_sent(1,{58,{0xa5}}),"duplicate_lobby_confirmation_repeated_observer");
    require(registry.notify_lobby_sent(2,{58,{0xa5}}) && !registry.has_room(9,3) &&
        !registry.notify_lobby_sent(999,{58,{0xa5}}),"all_lobby_sends_did_not_retire_exact_generation");
    require(confirmed==std::array<int,2>{1,1} && lobby_confirmed==std::array<int,2>{1,1},"registry_hook_count_wrong");
    registry.cancel_room(9,3);
    require(cleaned==2 && !registry.completed_room(9,3) && !registry.notify_lobby_sent(1,{58,{0xa5}}),"cancelled_completion_not_retired");
    rejects([&]{first.sent(a,{299,{}});},"richonline_game_plan_cancelled");
}
void absent_plan_observers_do_not_enable_send_tracking() {
    int cleaned=0;
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& snapshot) {
        std::vector<RichonlineGamePlan> plans; for(const auto& peer:snapshot.participants)plans.push_back(plan(peer,cleaned));return plans;
    },9,std::chrono::seconds(30));
    registry.prepare(room()); auto callbacks=registry.callbacks();
    const auto descriptor=richonline_expected_admission({9,3,11},redirect(1));
    require(callbacks.authorize_admission(descriptor) && !callbacks.sent_enabled(descriptor),"absent_plan_observer_tracked_output");
    callbacks.sent(descriptor,{299,{}});
    require(!registry.completed_room(9,3) && !registry.notify_lobby_sent(1,{58,{}}),"absent_plan_completion_invented");
    registry.shutdown();
}
void terminal_binding_survives_disconnect_and_all_members_can_restart() {
    struct Round {
        std::uint8_t tag;
        bool pending=false;
        std::array<bool,2> waiting_lobby{};
        std::array<int,2> cleaned{},confirmed{};
        bool fail_first=false;
    };
    std::vector<std::shared_ptr<Round>> rounds;
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& snapshot) {
        const auto round=std::make_shared<Round>(); round->tag=static_cast<std::uint8_t>(16*(rounds.size()+1));
        rounds.push_back(round);
        std::vector<RichonlineGamePlan> plans;
        for(const auto& peer:snapshot.participants) {
            const auto index=static_cast<std::size_t>(peer.slot);
            RichonlineGamePlan value{peer.connection,peer.actor,redirect(static_cast<std::uint8_t>(round->tag+peer.connection)),
                [] {return std::vector<Frame>{};},[](const Envelope299&,View) {return std::vector<Frame>{};},
                [round,index] {++round->cleaned[index];}};
            value.game_finished=[round,index] {return round->waiting_lobby[index];};
            value.terminal_pending=[round] {return round->pending;};
            value.lobby_sent=[round,index](const Frame& frame) {
                if(frame.wire_type!=58 || frame.payload!=Bytes{round->tag,static_cast<std::uint8_t>(index)}) return;
                if(round->fail_first && index==0) throw CodecError("injected_lobby_checkpoint_failure");
                ++round->confirmed[index]; round->waiting_lobby[index]=false;
            };
            plans.push_back(std::move(value));
        }
        return plans;
    },9,std::chrono::seconds(30));
    registry.prepare(room()); const auto first_round=rounds.at(0);
    auto first=registry.callbacks(),second=registry.callbacks();
    const auto a=richonline_expected_admission({9,3,11},redirect(17));
    const auto b=richonline_expected_admission({9,3,22},redirect(18));
    require(first.authorize_admission(a) && second.authorize_admission(b),"terminal_lifecycle_admission_failed");
    // Results are delivering; the client's six-second presentation is not yet over.
    first_round->pending=true; first.disconnected(a); first.disconnected(a);
    require(first_round->cleaned==std::array<int,2>{1,0} && registry.has_room(9,3) && !registry.completed_room(9,3),
        "presentation_delay_disconnect_lost_terminal_binding");
    require(!registry.notify_lobby_sent(1,{58,{16,0}}),"presentation_delay_confirmed_lobby_too_early");
    first_round->waiting_lobby={true,true};
    require(registry.completed_room(9,3),"delayed_terminal_binding_did_not_become_ready");
    require(!registry.notify_lobby_sent(999,{58,{16,0}}) && !registry.notify_lobby_sent(1,{57,{16,0}}) &&
        !registry.notify_lobby_sent(1,{58,{16}}),"wrong_connection_partial_or_wrong_frame_retired_terminal");
    first_round->fail_first=true;
    rejects([&] {registry.notify_lobby_sent(1,{58,{16,0}});},"injected_lobby_checkpoint_failure");
    require(registry.has_room(9,3) && first_round->confirmed==std::array<int,2>{0,0},"failed_checkpoint_retired_binding");
    first_round->fail_first=false;
    require(registry.notify_lobby_sent(1,{58,{16,0}}) && registry.completed_room(9,3) && registry.has_room(9,3),
        "first_confirmation_discarded_second_participant");
    require(!registry.notify_lobby_sent(1,{58,{16,0}}) && first_round->confirmed==std::array<int,2>{1,0},
        "duplicate_confirmation_changed_terminal_state");
    rejects([&] {registry.prepare(room());},"richonline_game_plan_already_registered");
    require(rounds.size()==1,"premature_restart_created_new_provider_state");
    require(registry.notify_lobby_sent(2,{58,{16,1}}) && !registry.has_room(9,3) && !registry.completed_room(9,3),
        "all_terminal_confirmations_not_retired");
    require(first_round->cleaned==std::array<int,2>{1,1},"completed_generation_cleanup_not_once");
    registry.prepare(room()); require(rounds.size()==2,"same_connections_could_not_prepare_next_round");
    first.disconnected(a); second.disconnected(b);
    require(registry.has_room(9,3),"old_transport_disconnect_cancelled_new_generation");
    auto new_first=registry.callbacks(),new_second=registry.callbacks();
    const auto next_a=richonline_expected_admission({9,3,11},redirect(33));
    const auto next_b=richonline_expected_admission({9,3,22},redirect(34));
    require(!new_first.authorize_admission(a) && new_first.authorize_admission(next_a) && new_second.authorize_admission(next_b),
        "retirement_reused_old_admission_token_or_blocked_next_round");
    const auto second_round=rounds.at(1); second_round->pending=true;second_round->waiting_lobby={true,true};
    require(!registry.notify_lobby_sent(1,{58,{16,0}}) && registry.has_room(9,3),"stale_previous_result_confirmed_new_generation");
    require(registry.notify_lobby_sent(1,{58,{32,0}}) && registry.notify_lobby_sent(2,{58,{32,1}}),"new_generation_result_not_confirmed");
    require(!registry.has_room(9,3) && second_round->cleaned==std::array<int,2>{1,1},"new_generation_cleanup_failed");
}
void real_tcp_terminal_disconnect_and_second_round() {
    struct Network {
        Network() {WSADATA data{};require(WSAStartup(MAKEWORD(2,2),&data)==0,"lifecycle_tcp_winsock");}
        ~Network() {WSACleanup();}
    } network;
    struct TcpPeer {
        SOCKET socket=INVALID_SOCKET;
        explicit TcpPeer(std::uint16_t port) {
            socket=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);require(socket!=INVALID_SOCKET,"lifecycle_tcp_socket");
            const DWORD timeout=2000;
            require(setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout))==0,"lifecycle_tcp_timeout");
            sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(port);
            require(inet_pton(AF_INET,"127.0.0.1",&address.sin_addr)==1 &&
                connect(socket,reinterpret_cast<const sockaddr*>(&address),sizeof(address))==0,"lifecycle_tcp_connect");
        }
        ~TcpPeer() {close();}
        void close() {if(socket!=INVALID_SOCKET){closesocket(socket);socket=INVALID_SOCKET;}}
        void send(View wire) {
            while(!wire.empty()) {const auto count=::send(socket,reinterpret_cast<const char*>(wire.data()),static_cast<int>(wire.size()),0);
                require(count>0,"lifecycle_tcp_send");wire=wire.subspan(static_cast<std::size_t>(count));}
        }
        void reply(std::uint32_t type) {
            Bytes wire(9);std::size_t offset=0;
            while(offset<wire.size()) {const auto count=recv(socket,reinterpret_cast<char*>(wire.data()+offset),static_cast<int>(wire.size()-offset),0);
                require(count>0,"lifecycle_tcp_reply_missing");offset+=static_cast<std::size_t>(count);}
            require(decode_frame(wire,{Channel::game_s2c,{},ClientVersion::richonline}).wire_type==type,"lifecycle_tcp_reply_type");
        }
    };
    struct Round {
        std::uint8_t tag=0;
        std::atomic_bool delay_ready{false};
        std::array<std::atomic_bool,2> terminal{},sent{},lobby_done{};
        std::array<std::atomic_int,2> cleaned{};
    };
    std::vector<std::shared_ptr<Round>> rounds;
    std::mutex mutex;std::condition_variable changed;bool listening=false;
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& snapshot) {
        auto round=std::make_shared<Round>();round->tag=static_cast<std::uint8_t>(16*(rounds.size()+1));rounds.push_back(round);
        std::vector<RichonlineGamePlan> plans;
        for(const auto& peer:snapshot.participants) {
            const auto index=static_cast<std::size_t>(peer.slot);
            RichonlineGamePlan value{peer.connection,peer.actor,redirect(static_cast<std::uint8_t>(round->tag+peer.connection)),
                [] {return std::vector<Frame>{{55,{0x43}}};},
                [round,index](const Envelope299&,View) {round->terminal[index]=true;return std::vector<Frame>{{56,{0x44}}};},
                [&,round,index] {const std::lock_guard lock(mutex);++round->cleaned[index];changed.notify_all();}};
            value.sent=[round,index](const Frame& frame) {if(frame.wire_type==56)round->sent[index]=true;};
            value.game_finished=[round,index] {return round->sent[index] && round->delay_ready && !round->lobby_done[index];};
            value.terminal_pending=[round,index] {return round->terminal[index].load();};
            value.lobby_sent=[round,index](const Frame& frame) {
                if(frame.wire_type==58 && frame.payload==Bytes{round->tag,static_cast<std::uint8_t>(index)})round->lobby_done[index]=true;
            };
            plans.push_back(std::move(value));
        }
        return plans;
    },9,std::chrono::seconds(30));
    GameService service({"127.0.0.1",0,ClientVersion::richonline},[&] {return registry.callbacks();},[&](const std::string&) {
        if(service.bound_port()!=0) {const std::lock_guard lock(mutex);listening=true;changed.notify_all();}
    });
    struct Running {
        GameService& service;std::exception_ptr error;std::thread thread;
        explicit Running(GameService& value):service(value),thread([this]{try{service.run();}catch(...){error=std::current_exception();}}) {}
        ~Running() {service.stop();if(thread.joinable())thread.join();}
    } running(service);
    {std::unique_lock lock(mutex);require(changed.wait_for(lock,std::chrono::seconds(5),[&]{return listening;}),"lifecycle_tcp_listener");}
    for(unsigned cycle=0;cycle<2;++cycle) {
        registry.prepare(room());const auto round=rounds.back();
        TcpPeer first(service.bound_port()),second(service.bound_port());
        const std::array<GameAdmission,2> admissions{
            richonline_expected_admission({9,3,11},redirect(static_cast<std::uint8_t>(round->tag+1))),
            richonline_expected_admission({9,3,22},redirect(static_cast<std::uint8_t>(round->tag+2)))};
        first.send(encode_frame(encode_game_admission(admissions[0],ClientVersion::richonline),{Channel::game_c2s,{},ClientVersion::richonline}));
        second.send(encode_frame(encode_game_admission(admissions[1],ClientVersion::richonline),{Channel::game_c2s,{},ClientVersion::richonline}));
        first.reply(55);second.reply(55);
        const auto request=encode_frame(encode_envelope({0,1,{0x97,0x6b,0x98,0x6c,0x99,0x6b,0x9a,0x6d},{}},ClientVersion::richonline),
            {Channel::game_c2s,{},ClientVersion::richonline});
        first.send(request);second.send(request);first.reply(56);second.reply(56);
        first.close();second.close();
        {std::unique_lock lock(mutex);require(changed.wait_for(lock,std::chrono::seconds(5),[&]{return round->cleaned[0]==1 && round->cleaned[1]==1;}),"lifecycle_tcp_disconnect_not_released");}
        require(round->sent[0] && round->sent[1] && registry.has_room(9,3) && !registry.completed_room(9,3),
            "real_tcp_terminal_disconnect_lost_delayed_binding");
        round->delay_ready=true;require(registry.completed_room(9,3),"real_tcp_terminal_delay_not_resumable");
        require(registry.notify_lobby_sent(1,{58,{round->tag,0}}) && registry.has_room(9,3) &&
            !registry.notify_lobby_sent(1,{58,{round->tag,0}}),"real_tcp_first_or_duplicate_lobby_ack_retired_room");
        require(registry.notify_lobby_sent(2,{58,{round->tag,1}}) && !registry.has_room(9,3),"real_tcp_all_lobby_ack_not_retired");
        require(round->cleaned[0]==1 && round->cleaned[1]==1,"real_tcp_terminal_cleanup_repeated");
    }
    service.stop();running.thread.join();if(running.error)std::rethrow_exception(running.error);
}
}
int main() {
    try { all_members_register_before_redirect_and_echo_is_once_only(); partial_provider_failure_creates_no_admission();
        pending_expiry_and_game_disconnect_cancel_the_whole_room();
        cancellation_waits_for_running_action_before_cleanup();
        shutdown_cleans_unconsumed_plans_and_prevents_restart();
        poll_requires_matching_admission_and_supports_an_absent_handler();
        cancellation_waits_for_running_poll_before_cleanup();
        successful_sends_propagate_without_retiring_live_game();
        absent_plan_observers_do_not_enable_send_tracking();
        terminal_binding_survives_disconnect_and_all_members_can_restart();
        real_tcp_terminal_disconnect_and_second_round();
        std::cout << "richonline game registry tests PASS\n"; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
