#include "original_game_registry.hpp"

#include <algorithm>
#include <iostream>
#include <memory>
#include <string_view>
#include <thread>

namespace {
using namespace richnet;
const AdmissionClock::time_point now{};

void check(bool condition, std::string_view reason) {
    if (!condition) throw std::runtime_error(std::string(reason));
}
template<class Action> void rejects(Action action, std::string_view code) {
    try { action(); }
    catch (const CodecError& error) { check(error.what() == code, "wrong registry rejection"); return; }
    throw std::runtime_error("expected registry rejection: " + std::string(code));
}
struct Calls { int ready{}; int action{}; int closed{}; Bytes input; };

OriginalGamePlan plan(const std::shared_ptr<Calls>& calls, std::uint8_t tag = 0x91) {
    OriginalInitPlayer first{12, 5, 2, {1,2,3,4,5,6,7,8,9,10}, 0xa1};
    OriginalInitPlayer self{25, 9, 3, {10,9,8,7,6,5,4,3,2,1}, 0xa2};
    OriginalGamePlan result;
    result.startup = {
        {0x1234, 17.5, {2024,2,29,4}, 1, {first,self}, 0x88, {0xfa,tag,0x7f}},
        {0x1234, 0x89abcdefU, 7, {{123,456,789},{234,567,890}}, {0xe1,tag,0xe2}},
        {19,-3,{0x11,0x22,0x80,0xff}}};
    result.map_ready = [calls,tag] { ++calls->ready; return std::vector<Bytes>{{0x71,tag}}; };
    result.action = [calls,tag](View bytes) {
        ++calls->action;
        calls->input.assign(bytes.begin(),bytes.end());
        return std::vector<Bytes>{{0x72,tag}};
    };
    result.disconnected = [calls] { ++calls->closed; };
    return result;
}
OriginalGameReservation reservation(std::uint64_t owner = 1) {
    return {owner,{2,3,25},{{192,0,2,21},18602},now + std::chrono::seconds(30)};
}
GameAdmission client_echo(const Frame& redirect, OriginalAdmissionIdentity identity = {2,3,25}) {
    check(redirect.wire_type == 22 && redirect.payload.size() == 18, "registry must issue original packed18 redirect");
    const View bytes(redirect.payload);
    GameAdmission result{identity.room_id,identity.game_id,identity.user_id,{},read_le(bytes.subspan(6,4)),{}};
    std::copy(bytes.begin()+10,bytes.begin()+18,result.opaque8.begin());
    result.legacy_fields = std::array<std::uint32_t,2>{0,0};
    return result;
}

void complete_plan_and_callbacks_survive_reservation() {
    OriginalGameRegistry registry;
    const auto calls = std::make_shared<Calls>();
    const auto redirect = registry.prepare(reservation(),plan(calls),now);
    const Bytes endpoint{192,0,2,21,0xaa,0x48};
    check(std::equal(endpoint.begin(),endpoint.end(),redirect.payload.begin()), "registry changed endpoint bytes");
    const auto admission = client_echo(redirect);
    check(admission.field20 <= 0x7fffffffU, "registry token A fails original signed gate");
    const auto received = registry.consume(admission,now);
    check(received.has_value(), "prepared admission has no plan");
    const Bytes init{
        0,0x40,0x34,0x12, 0,0,0,0,0,0x80,0x31,0x40, 0xe8,7,2,29,4,2,1,0x88,
        12,0,5,0,2,1,2,3,4,5,6,7,8,9,10,0xa1,
        25,0,9,0,3,10,9,8,7,6,5,4,3,2,1,0xa2, 0xfa,0x91,0x7f};
    const Bytes snapshot{4,0x40,0x34,0x12,0xef,0xcd,0xab,0x89,7,0,0,0,
        123,0,0,0,0xc8,1,0,0,0x15,3,0,0,0xea,0,0,0,0x37,2,0,0,0x7a,3,0,0,0xe1,0x91,0xe2};
    check(encode_original_board_init(received->startup.init) == init, "startup init or opaque bytes lost");
    check(encode_original_board_snapshot(received->startup.snapshot) == snapshot, "startup snapshot or opaque bytes lost");
    const auto& envelope = received->startup.envelope;
    check(envelope.inner_type == 19 && envelope.mode == -3 &&
          envelope.tail == std::array<std::uint8_t,4>{0x11,0x22,0x80,0xff}, "envelope metadata lost");
    check(received->map_ready() == std::vector<Bytes>{{0x71,0x91}}, "ready callback lost closure state");
    check(received->action(Bytes{0x80,0,0xfe}) == std::vector<Bytes>{{0x72,0x91}}, "action callback lost closure state");
    received->disconnected();
    check(calls->ready == 1 && calls->action == 1 && calls->closed == 1 && calls->input == Bytes({0x80,0,0xfe}),
          "callbacks do not operate on original shared state");
    check(!registry.consume(admission,now), "consumed original plan replayed");
}

void mismatched_fields_do_not_consume_plan() {
    OriginalGameRegistry registry;
    const auto expected = client_echo(registry.prepare(reservation(),plan(std::make_shared<Calls>()),now));
    for (unsigned index = 0; index != 9; ++index) {
        auto wrong = expected;
        switch (index) {
        case 0: ++wrong.id0; break;
        case 1: ++wrong.id1; break;
        case 2: ++wrong.id2; break;
        case 3: wrong.opaque8[0] ^= 0x80; break;
        case 4: wrong.opaque8[4] ^= 0x80; break;
        case 5: wrong.field20 ^= 0x40; break;
        case 6: ++(*wrong.legacy_fields)[0]; break;
        case 7: ++(*wrong.legacy_fields)[1]; break;
        case 8: wrong.legacy_fields.reset(); break;
        }
        check(!registry.consume(wrong,now), "wrong descriptor consumed original plan");
    }
    check(registry.consume(expected,now).has_value(), "wrong descriptor erased valid plan");
}

void cancel_and_replacement_are_owner_scoped() {
    OriginalGameRegistry registry(2);
    const auto calls = std::make_shared<Calls>();
    const auto old = client_echo(registry.prepare(reservation(1),plan(calls,0x31),now));
    auto other = reservation(2); other.identity.game_id = 4;
    const auto retained = client_echo(registry.prepare(other,plan(calls,0x32),now),other.identity);
    auto replacement = reservation(1); replacement.identity.game_id = 5;
    const auto current = client_echo(registry.prepare(replacement,plan(calls,0x33),now),replacement.identity);
    check(!registry.consume(old,now), "replaced descriptor remains usable");
    auto result = registry.consume(current,now);
    check(result && result->map_ready() == std::vector<Bytes>{{0x71,0x33}}, "replacement returned old plan");
    registry.cancel(1);
    check(registry.consume(retained,now).has_value(), "cancel affected unrelated owner");
    const auto cancelled = client_echo(registry.prepare(reservation(1),plan(calls),now));
    registry.cancel(1); registry.cancel(1);
    check(!registry.consume(cancelled,now), "cancelled plan remains usable");
}

void expiry_and_capacity_boundaries() {
    const auto calls = std::make_shared<Calls>();
    OriginalGameRegistry registry(1);
    const auto entry = reservation();
    const auto first = client_echo(registry.prepare(entry,plan(calls),now));
    rejects([&] { registry.prepare(reservation(2),plan(calls),now); }, "game_admission_capacity_reached");
    check(registry.consume(first,entry.expires_at-AdmissionClock::duration(1)).has_value(), "ticket expired before exact deadline");
    const auto expired = client_echo(registry.prepare(entry,plan(calls),now));
    check(!registry.consume(expired,entry.expires_at), "ticket accepted at expiry boundary");
    auto next = reservation(2); next.expires_at += std::chrono::seconds(30);
    const auto second = client_echo(registry.prepare(next,plan(calls),entry.expires_at));
    check(registry.consume(second,entry.expires_at).has_value(), "expired reservation did not free capacity");
    const auto abandoned = client_echo(registry.prepare(entry,plan(calls),now));
    const auto reclaimed = client_echo(registry.prepare(next,plan(calls),entry.expires_at));
    check(!registry.consume(abandoned,entry.expires_at), "prepare retained expired reservation");
    check(registry.consume(reclaimed,entry.expires_at).has_value(), "prepare did not reclaim expired capacity");
    auto invalid = reservation(); invalid.expires_at = now;
    rejects([&] { registry.prepare(invalid,plan(calls),now); }, "game_admission_expiry_invalid");
    invalid = reservation(0);
    rejects([&] { registry.prepare(invalid,plan(calls),now); }, "game_admission_owner_invalid");
    OriginalGameRegistry empty(0);
    rejects([&] { empty.prepare(entry,plan(calls),now); }, "game_admission_capacity_invalid");
}

void invalid_replacement_keeps_original_plan() {
    OriginalGameRegistry registry;
    const auto calls = std::make_shared<Calls>();
    const auto original = client_echo(registry.prepare(reservation(),plan(calls,0x51),now));
    auto invalid = plan(calls); ++invalid.startup.snapshot.gmsv_id;
    rejects([&] { registry.prepare(reservation(),invalid,now); }, "original_board_startup_instance_mismatch");
    invalid = plan(calls); invalid.map_ready = {};
    rejects([&] { registry.prepare(reservation(),invalid,now); }, "original_game_strategy_required");
    invalid = plan(calls); invalid.action = {};
    rejects([&] { registry.prepare(reservation(),invalid,now); }, "original_game_strategy_required");
    invalid = plan(calls); invalid.startup.init.players[1].lobby_user_id = 26;
    rejects([&] { registry.prepare(reservation(),invalid,now); }, "original_game_startup_identity_mismatch");
    auto bad_endpoint = reservation(); bad_endpoint.endpoint.port = 0;
    rejects([&] { registry.prepare(bad_endpoint,plan(calls),now); }, "original_game_redirect_port_invalid");
    auto bad_expiry = reservation(); bad_expiry.expires_at = now;
    rejects([&] { registry.prepare(bad_expiry,plan(calls),now); }, "game_admission_expiry_invalid");
    const auto result = registry.consume(original,now);
    check(result && result->map_ready() == std::vector<Bytes>{{0x71,0x51}}, "invalid replacement overwrote original plan");
}

void concurrent_consume_delivers_plan_once() {
    OriginalGameRegistry registry;
    const auto calls = std::make_shared<Calls>();
    const auto expected = client_echo(registry.prepare(reservation(),plan(calls),now));
    std::array<std::optional<OriginalGamePlan>,4> results;
    std::array<std::thread,4> consumers;
    for (std::size_t index = 0; index != consumers.size(); ++index)
        consumers[index] = std::thread([&,index] { results[index] = registry.consume(expected,now); });
    for (auto& consumer : consumers) consumer.join();
    unsigned count = 0;
    for (auto& result : results) if (result) { ++count; result->map_ready(); }
    check(count == 1 && calls->ready == 1, "concurrent admission delivered multiple plans");
}
}

int main() {
    try {
        complete_plan_and_callbacks_survive_reservation();
        mismatched_fields_do_not_consume_plan();
        cancel_and_replacement_are_owner_scoped();
        expiry_and_capacity_boundaries();
        invalid_replacement_keeps_original_plan();
        concurrent_consume_delivers_plan_once();
        std::cout << "PASS original game registry lifecycle and complete plan binding\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
