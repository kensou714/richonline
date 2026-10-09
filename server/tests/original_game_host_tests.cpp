#include "original_game_host.hpp"
#include <algorithm>
#include <atomic>
#include <barrier>
#include <future>
#include <iostream>
#include <thread>

namespace {
using namespace richnet;
void check(bool value,std::string_view reason) { if (!value) throw std::runtime_error(std::string(reason)); }
template<class Action> void rejects(Action action,std::string_view expected) {
    try { action(); } catch (const CodecError& error) { check(error.what() == expected,std::string("unexpected error: ")+error.what()); return; }
    throw std::runtime_error("expected error missing: "+std::string(expected));
}
struct Counts { std::atomic<unsigned> ready{0}, actions{0}, closed{0}; };
struct Clock {
    std::atomic<std::int64_t> millis{1000};
    AdmissionClock::time_point now() const { return AdmissionClock::time_point{}+std::chrono::milliseconds(millis.load()); }
};
OriginalRoomSnapshot snapshot(std::uint64_t generation = 1) {
    return {generation,2,3,12,{{0x91,0x27},"test.emp",2},{{12,0,0,Bytes(268,0xa1)},{25,1,1,Bytes(268,0xb2)}}};
}
OriginalGamePlan plan(std::uint32_t user,const std::shared_ptr<Counts>& counts) {
    OriginalGamePlan result;
    result.startup = {{0x1234,17.5,{2024,2,29,4},static_cast<std::uint8_t>(user == 12 ? 0 : 1),
        {{12,5,2,{1,2,3,4,5,6,7,8,9,10},0xa1},{25,9,3,{10,9,8,7,6,5,4,3,2,1},0xa2}},0x88,{0xfa,0x91}},
        {0x1234,0x89ab3456,7,{{123,456,789},{234,567,890}},{0xe1,0x92}}, {19,-3,{0x11,0x22,0x80,0xff}}};
    result.map_ready = [counts] { ++counts->ready; return std::vector<Bytes>{}; };
    result.action = [counts](View) { ++counts->actions; return std::vector<Bytes>{{0x0b,0x40,0x34,0x12,1}}; };
    result.disconnected = [counts] { ++counts->closed; };
    return result;
}
OriginalRoomGameProvider provider(const std::shared_ptr<Counts>& counts) {
    return [counts](const OriginalRoomSnapshot& room) {
        std::vector<OriginalGamePlanForUser> result;
        for (const auto& member : room.players) result.push_back({member.user_id,plan(member.user_id,counts)});
        return result;
    };
}
GameAdmission echo(const OriginalRoomRedirect& redirect) {
    const View bytes(redirect.message.payload);
    check(redirect.message.wire_type == 22 && bytes.size() == 18,"original packed18 redirect required");
    OriginalGameRedirect target{{{127,0,0,1},19022},read_le(bytes.subspan(6,4)),read_le(bytes.subspan(10,4)),read_le(bytes.subspan(14,4))};
    return original_expected_admission({2,3,redirect.user_id},target);
}
Bytes admission_packet(const GameAdmission& admission) {
    return encode_frame(encode_game_admission(admission,ClientVersion::legacy),{Channel::game_c2s,{},ClientVersion::legacy});
}
Bytes message_packet(View plain) {
    return encode_frame(encode_envelope({0,-1,encode_inner(plain,Bytes(plain.size()+2,0xb5)),{0x11,0x22,0x33,0x44}}),
                        {Channel::game_c2s,{},ClientVersion::legacy});
}
void complete_lifecycle_and_generation_reuse() {
    const auto counts = std::make_shared<Counts>(); Clock clock;
    OriginalGameHost host(provider(counts),{{127,0,0,1},19022},std::chrono::milliseconds(100),[&] { return clock.now(); });
    const auto redirects = host.prepare(snapshot());
    check(redirects.size() == 2 && !host.status(1).finished && !host.status(1).admitted,"pending match has two member redirects");
    const auto first = echo(redirects[0]), second = echo(redirects[1]);
    auto wrong = first; wrong.field20 ^= 1;
    auto rejected = host.callbacks(); check(!rejected.authorize_admission(wrong),"tamper must not consume valid reservation");
    GameSession one(ClientVersion::legacy,host.callbacks()), two(ClientVersion::legacy,host.callbacks());
    const auto packets = one.feed(admission_packet(first));
    check(packets.size() == 1,"admission sends one initialization");
    const auto init = decode_inner(decode_envelope(decode_frame(packets[0],{Channel::game_s2c,{}})).encoded);
    check(init == encode_original_board_init(plan(12,counts).startup.init),"complete opaque initialization survives host");
    check(host.status(1).admitted && !host.finished(1),"admitted status records first member");
    two.feed(admission_packet(second));
    clock.millis = 1200;
    check(!host.finished(1),"fully admitted active match does not expire at admission deadline");
    one.feed(message_packet(Bytes{0,0}));
    one.feed(message_packet(Bytes{16,0,0x56,0x34,0,0,0,0}));
    check(counts->ready == 1 && counts->actions == 1,"authorized original actions reach strategy");
    auto replay = host.callbacks(); check(!replay.authorize_admission(first),"consumed token cannot replay");
    one.finish();
    check(host.finished(1) && counts->closed == 2,"one member EOF closes all match strategies exactly once");
    rejects([&] { two.feed(message_packet(Bytes{1,0})); },"original_game_host_match_closed");
    two.finish(); host.cancel(1);
    check(counts->closed == 2,"repeat EOF/cancel leaves cleanup once");
    rejects([&] { host.prepare(snapshot()); },"original_game_host_generation_duplicate");
    const auto next = host.prepare(snapshot(2));
    check(next.size() == 2 && !host.callbacks().authorize_admission(first),"reused room/user IDs cannot reuse old generation token");
    host.shutdown(); check(counts->closed == 4,"shutdown cleans pending next generation");
    rejects([&] { host.status(999); },"original_game_host_generation_missing");
    rejects([&] { host.prepare(snapshot(3)); },"original_game_host_stopped");
}
void expiry_and_cleanup_reentry() {
    const auto counts = std::make_shared<Counts>(); Clock clock;
    OriginalGameHost* address = nullptr;
    auto create = [&,base = provider(counts)](const OriginalRoomSnapshot& room) {
        auto plans = base(room);
        for (auto& entry : plans) entry.plan.disconnected = [&,generation = room.generation] {
            ++counts->closed; check(address->finished(generation),"cleanup may reenter host without global mutex deadlock");
        };
        return plans;
    };
    OriginalGameHost host(create,{{127,0,0,1},19022},std::chrono::milliseconds(100),[&] { return clock.now(); }); address = &host;
    const auto redirects = host.prepare(snapshot());
    auto connected = host.callbacks(); check(connected.authorize_admission(echo(redirects[0])),"first member admitted");
    connected.admitted(echo(redirects[0])); clock.millis = 1100;
    check(host.status(1).finished && host.status(1).admitted && counts->closed == 2,"missing second admission expires entire match at exact deadline");
    check(!host.callbacks().authorize_admission(echo(redirects[1])),"expired other-member token revoked");
    rejects([&] { connected.poll(echo(redirects[0])); },"original_game_host_match_closed");
    connected.disconnected(echo(redirects[0]));
    host.prepare(snapshot(2)); clock.millis = 1200;
    check(host.status(2).finished && !host.status(2).admitted && counts->closed == 4,"zero-admission timeout retains distinct lobby recovery status");
}
void invalid_prepare_is_atomic() {
    const auto counts = std::make_shared<Counts>(); Clock clock;
    auto invalid = [base = provider(counts)](const OriginalRoomSnapshot& room) {
        auto plans = base(room); plans.back().plan.startup.snapshot.gmsv_id = 8; return plans;
    };
    OriginalGameHost host(invalid,{{127,0,0,1},19022},std::chrono::milliseconds(100),[&] { return clock.now(); });
    rejects([&] { host.prepare(snapshot()); },"original_board_startup_instance_mismatch");
    check(host.finished(1) && counts->closed == 2,"invalid second plan rolls back entire preparation and cleans both strategies");
    host.shutdown(); check(counts->closed == 2,"failed preparation is not cleaned twice");
    auto duplicate = snapshot(2); duplicate.players[1].user_id = 12;
    rejects([&] { host.prepare(duplicate); },"original_game_host_snapshot_invalid");
}
void concurrent_cancel_and_consume() {
    const auto counts = std::make_shared<Counts>(); Clock clock;
    std::promise<void> entered, resume; auto gate = resume.get_future().share();
    auto delayed = [&,base = provider(counts)](const OriginalRoomSnapshot& room) {
        entered.set_value(); gate.wait(); return base(room);
    };
    OriginalGameHost delayed_host(delayed,{{127,0,0,1},19022},std::chrono::milliseconds(100),[&] { return clock.now(); });
    auto preparing = std::async(std::launch::async,[&] {
        rejects([&] { delayed_host.prepare(snapshot()); },"original_game_host_match_closed");
    });
    entered.get_future().wait(); delayed_host.cancel(1); resume.set_value(); preparing.get();
    check(counts->closed == 2,"cancel during provider prevents redirects and cleans returned plans");
    OriginalGameHost host(provider(counts),{{127,0,0,1},19022},std::chrono::milliseconds(100),[&] { return clock.now(); });
    const auto redirects = host.prepare(snapshot()); const auto admission = echo(redirects[0]);
    std::array<GameCallbacks,4> clients{host.callbacks(),host.callbacks(),host.callbacks(),host.callbacks()};
    std::array<std::thread,4> threads; std::atomic<unsigned> accepted{0};
    for (std::size_t i = 0; i < threads.size(); ++i) threads[i] = std::thread([&,i] { if (clients[i].authorize_admission(admission)) ++accepted; });
    for (auto& thread : threads) thread.join();
    check(accepted == 1,"concurrent identical authorization consumes token once");
    host.cancel(1); check(counts->closed == 4,"concurrent replay does not duplicate prepared-strategy cleanup");
}
void callbacks_outlive_host() {
    const auto counts = std::make_shared<Counts>(); Clock clock;
    GameCallbacks callbacks; GameAdmission admission;
    {
        OriginalGameHost host(provider(counts),{{127,0,0,1},19022},std::chrono::milliseconds(100),[&] { return clock.now(); });
        admission = echo(host.prepare(snapshot())[0]); callbacks = host.callbacks();
        check(callbacks.authorize_admission(admission),"live host authorizes callback");
    }
    check(counts->closed == 2,"destruction shuts down all prepared strategies");
    rejects([&] { callbacks.admitted(admission); },"original_game_host_match_closed");
    callbacks.disconnected(admission); check(counts->closed == 2,"outliving callback releases without stale host access or repeated cleanup");
}
void partial_registry_failure_and_slow_provider() {
    const auto counts = std::make_shared<Counts>(); Clock clock;
    OriginalGameHost host(provider(counts),{{127,0,0,1},19022},std::chrono::milliseconds(100),[&] { return clock.now(); });
    GameAdmission retained;
    for (std::uint64_t generation = 1; generation <= 15; ++generation) {
        const auto redirects = host.prepare(snapshot(generation));
        if (generation == 1) retained = echo(redirects[0]);
    }
    auto single = snapshot(16); single.players.resize(1); host.prepare(single);
    rejects([&] { host.prepare(snapshot(17)); },"game_admission_capacity_reached");
    check(host.finished(17) && counts->closed == 2,"second reservation capacity failure cleans both plans after rollback");
    check(host.callbacks().authorize_admission(retained),"partial failed preparation preserves unrelated live reservation");
    auto slow = [&,base = provider(counts)](const OriginalRoomSnapshot& room) { clock.millis = 1100; return base(room); };
    OriginalGameHost slow_host(slow,{{127,0,0,1},19022},std::chrono::milliseconds(100),[&] { return clock.now(); });
    rejects([&] { slow_host.prepare(snapshot()); },"original_game_host_prepare_expired");
    check(slow_host.finished(1),"provider exceeding TTL cannot publish already-expired redirects");
}
void retire_releases_generation_and_reports_cleanup_failure() {
    const auto counts = std::make_shared<Counts>(); Clock clock; std::vector<std::string> logs;
    auto create = [base = provider(counts),counts](const OriginalRoomSnapshot& room) {
        auto plans = base(room);
        if (room.generation == 20) for (auto& item : plans) item.plan.disconnected = [counts] { ++counts->closed; throw CodecError("test_cleanup_failed"); };
        return plans;
    };
    OriginalGameHost host(create,{{127,0,0,1},19022},std::chrono::milliseconds(100),[&] { return clock.now(); },[&](const auto& line) { logs.push_back(line); });
    const auto admission = echo(host.prepare(snapshot())[0]); auto stale = host.callbacks();
    check(stale.authorize_admission(admission),"old generation admission"); host.retire(1); host.retire(1); host.retire(999);
    rejects([&] { host.status(1); },"original_game_host_generation_missing");
    rejects([&] { host.prepare(snapshot()); },"original_game_host_generation_duplicate");
    for (std::uint64_t generation = 2; generation <= 20; ++generation) {
        host.prepare(snapshot(generation));
        stale.disconnected(admission);
        check(!host.finished(generation),"stale game disconnect cannot close reused room generation");
        host.retire(generation);
        rejects([&] { host.status(generation); },"original_game_host_generation_missing");
    }
    check(counts->closed == 40 && logs.size() == 2 && logs[0] == "original_game_host_cleanup_failed reason=test_cleanup_failed",
          "retirement releases every strategy once and reports both failed cleanup callbacks");
    rejects([&] { stale.admitted(admission); },"original_game_host_match_closed");
}
void consume_and_retire_linearize_admitted_status() {
    const auto counts = std::make_shared<Counts>(); Clock clock;
    OriginalGameHost host(provider(counts),{{127,0,0,1},19022},std::chrono::milliseconds(100),[&] { return clock.now(); });
    auto admission = echo(host.prepare(snapshot())[0]); auto client = host.callbacks();
    check(client.authorize_admission(admission) && host.retire(1).admitted,"authorization before retirement records admission");
    admission = echo(host.prepare(snapshot(2))[0]); client = host.callbacks();
    check(!host.retire(2).admitted && !client.authorize_admission(admission),"retirement before authorization revokes admission");
    for (std::uint64_t generation = 3; generation < 23; ++generation) {
        admission = echo(host.prepare(snapshot(generation))[0]); client = host.callbacks();
        std::barrier ready(2); bool accepted = false; OriginalGameHostStatus retired{false,false};
        std::thread consumer([&] { ready.arrive_and_wait(); accepted = client.authorize_admission(admission); });
        ready.arrive_and_wait(); retired = host.retire(generation); consumer.join();
        check(retired.finished && retired.admitted == accepted,"racing retirement returns final admission outcome");
        if (accepted) rejects([&] { client.admitted(admission); },"original_game_host_match_closed");
        else check(!client.authorize_admission(admission),"retired token remains revoked after losing race");
    }
    check(host.retire(999).finished && !host.retire(999).admitted,"unknown retirement is an unadmitted terminal result");
}
}
int main() {
    try {
        complete_lifecycle_and_generation_reuse(); expiry_and_cleanup_reentry(); invalid_prepare_is_atomic();
        concurrent_cancel_and_consume(); callbacks_outlive_host();
        partial_registry_failure_and_slow_provider();
        retire_releases_generation_and_reports_cleanup_failure();
        consume_and_retire_linearize_admitted_status();
        std::cout << "PASS original game host atomic preparation, generations, admission TTL, replay, concurrency and cleanup lifetime\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
