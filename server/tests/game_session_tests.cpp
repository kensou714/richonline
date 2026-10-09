#include "game_session.hpp"
#include "pending_game_admissions.hpp"

#include <algorithm>
#include <iostream>
#include <string_view>
#include <thread>

namespace {
using namespace richnet;
void require(bool value, const char* name) { if (!value) throw std::runtime_error(name); }
template<class Action> void rejects(Action action, const char* code) {
    try { action(); }
    catch (const CodecError& error) {
        require(std::string_view(error.what()) == code, "wrong_game_rejection_code");
        return;
    }
    throw std::runtime_error("expected_game_rejection");
}
GameAdmission descriptor(ClientVersion version) {
    GameAdmission result{3, 17, 25, {0x80,0x33,0xff,0x24,0x18,0x66,0xd0,0x7f}, 0xd5b3a112U, {}};
    if (version == ClientVersion::legacy) result.legacy_fields = std::array<std::uint32_t,2>{19, 23};
    return result;
}
Bytes admission_packet(ClientVersion version) {
    return encode_frame(encode_game_admission(descriptor(version), version), {Channel::game_c2s, {}, version});
}
Bytes message_packet(ClientVersion version) {
    const Envelope299 envelope{12, -3, {0x97,0x6b,0x98,0xeb,0x99,0x6b,0x9a,0x6c,0x9b,0x6b,0x9c,0x6f}, {}};
    auto value = envelope;
    if (version == ClientVersion::legacy) value.tail = {0x61,0x27,0x88,0x19};
    return encode_frame(encode_envelope(value, version), {Channel::game_c2s, {}, version});
}
void sessions_accept_each_version_without_losing_metadata() {
    for (const auto version : {ClientVersion::richonline, ClientVersion::legacy}) {
        int admits = 0, messages = 0, disconnects = 0;
        GameCallbacks callbacks;
        callbacks.authorize_admission = [&](const GameAdmission& value) { return value == descriptor(version); };
        callbacks.admitted = [&](const GameAdmission&) { ++admits; return std::vector<Frame>{{55, {0x81}}}; };
        callbacks.message = [&](const GameAdmission& value, const Envelope299& envelope, View plain) {
            require(value == descriptor(version), "descriptor_not_bound_to_gameplay");
            require(envelope.inner_type == 12 && envelope.mode == -3, "envelope_metadata_lost");
            require(envelope.tail == (version == ClientVersion::legacy ? std::array<std::uint8_t,4>{0x61,0x27,0x88,0x19} : std::array<std::uint8_t,4>{}), "envelope_tail_lost");
            const Bytes expected{1,0,0x80,0};
            require(std::equal(plain.begin(), plain.end(), expected.begin(), expected.end()), "gameplay_plain_bytes_wrong");
            ++messages;
            return std::vector<Frame>{{56, {0x82, 0x44}}};
        };
        callbacks.disconnected = [&](const GameAdmission&) { ++disconnects; };
        std::string logs;
        GameSession session(version, callbacks, [&](const std::string& line) { logs += line; });
        const auto admission = admission_packet(version);
        for (std::size_t index = 0; index + 1 < admission.size(); ++index)
            require(session.feed(View(admission).subspan(index,1)).empty(), "partial_admission_accepted");
        auto combined = Bytes{admission.back()};
        const auto message = message_packet(version);
        combined.insert(combined.end(), message.begin(), message.end());
        const auto responses = session.feed(combined);
        require(admits == 1 && messages == 1 && responses.size() == 2, "coalesced_game_flow_not_dispatched");
        require(decode_frame(responses[0], {Channel::game_s2c, {}, version}).wire_type == 55, "admission_reply_wrong");
        require(decode_frame(responses[1], {Channel::game_s2c, {}, version}).payload == Bytes({0x82,0x44}), "gameplay_reply_wrong");
        session.finish(); session.finish();
        require(disconnects == 1 && session.state() == GameState::closed, "disconnect_not_exactly_once");
        require(logs.find("357") == std::string::npos && logs.find("opaque") == std::string::npos, "admission_secret_logged");
    }
}
void rejected_admission_never_dispatches_gameplay() {
    GameCallbacks callbacks;
    int messages = 0;
    callbacks.authorize_admission = [](const GameAdmission&) { return false; };
    callbacks.message = [&](const GameAdmission&, const Envelope299&, View) { ++messages; return std::vector<Frame>{}; };
    GameSession session(ClientVersion::richonline, callbacks);
    auto combined = admission_packet(ClientVersion::richonline);
    const auto message = message_packet(ClientVersion::richonline);
    combined.insert(combined.end(), message.begin(), message.end());
    rejects([&] { session.feed(combined); }, "game_admission_not_authorized");
    require(messages == 0 && session.state() == GameState::closed, "unauthorized_gameplay_dispatched");
    rejects([&] { session.feed(message); }, "game_session_closed");
    session.finish();
    GameSession absent(ClientVersion::richonline, {});
    rejects([&] { absent.feed(admission_packet(ClientVersion::richonline)); }, "game_admission_provider_not_configured");
    absent.finish();
}
void session_rejects_cross_version_replay_and_incomplete_streams() {
    GameCallbacks callbacks;
    callbacks.authorize_admission = [](const GameAdmission&) { return true; };
    for (const auto version : {ClientVersion::richonline, ClientVersion::legacy}) {
        GameSession session(version, callbacks);
        const auto other = version == ClientVersion::richonline ? ClientVersion::legacy : ClientVersion::richonline;
        rejects([&] { session.feed(admission_packet(other)); }, "invalid_game_admission_length");
        session.finish();
        GameSession replay(version, callbacks);
        require(replay.feed(admission_packet(version)).empty(), "unexpected_admission_success_packet");
        rejects([&] { replay.feed(admission_packet(version)); }, "game_duplicate_admission");
        replay.finish();
        GameSession tail(version, callbacks);
        tail.feed(admission_packet(version));
        rejects([&] { tail.feed(message_packet(other)); }, "envelope_W_or_tail_length_mismatch");
        tail.finish();
    }
    int released = 0;
    callbacks.disconnected = [&](const GameAdmission&) { ++released; };
    GameSession partial(ClientVersion::richonline, callbacks);
    partial.feed(admission_packet(ClientVersion::richonline));
    partial.feed(Bytes{0x2b,1,0});
    rejects([&] { partial.finish(); }, "truncated_stream");
    partial.finish();
    require(released == 1 && partial.state() == GameState::closed, "partial_stream_did_not_release_admission");
}
void pending_descriptors_are_versioned_owned_expiring_and_single_use() {
    PendingGameAdmissions pending(2);
    const AdmissionClock::time_point now{};
    const auto expires = now + std::chrono::seconds(30);
    auto first = descriptor(ClientVersion::richonline);
    pending.prepare({10, ClientVersion::richonline, first, expires}, now);
    for (int field = 0; field < 5; ++field) {
        auto wrong = first;
        switch(field) {
        case 0: ++wrong.id0; break;
        case 1: ++wrong.id1; break;
        case 2: ++wrong.id2; break;
        case 3: wrong.opaque8[7] ^= 0x80; break;
        case 4: ++wrong.field20; break;
        }
        require(!pending.consume(ClientVersion::richonline, wrong, now), "mismatched_descriptor_consumed");
    }
    require(!pending.consume(ClientVersion::legacy, descriptor(ClientVersion::legacy), now), "cross_version_ticket_consumed");
    rejects([&] { pending.prepare({11, ClientVersion::richonline, first, expires}, now); }, "game_admission_descriptor_ambiguous");
    require(pending.consume(ClientVersion::richonline, first, now) == 10, "descriptor_owner_lost");
    require(!pending.consume(ClientVersion::richonline, first, now), "descriptor_replayed");
    pending.prepare({10, ClientVersion::richonline, first, expires}, now);
    auto replacement = first; ++replacement.id1;
    pending.prepare({10, ClientVersion::richonline, replacement, expires}, now);
    require(!pending.consume(ClientVersion::richonline, first, now), "replaced_descriptor_valid");
    pending.cancel(10);
    require(!pending.consume(ClientVersion::richonline, replacement, now), "cancelled_descriptor_valid");
    pending.prepare({10, ClientVersion::richonline, first, expires}, now);
    require(!pending.consume(ClientVersion::richonline, first, expires), "expired_descriptor_valid_at_boundary");
    const auto legacy = descriptor(ClientVersion::legacy);
    pending.prepare({20, ClientVersion::legacy, legacy, expires}, now);
    auto wrong_tail = legacy; ++(*wrong_tail.legacy_fields)[1];
    require(!pending.consume(ClientVersion::legacy, wrong_tail, now), "legacy_tail_ignored");
    require(pending.consume(ClientVersion::legacy, legacy, now) == 20, "legacy_owner_lost");
}
void concurrent_admission_can_only_consume_once() {
    PendingGameAdmissions pending;
    const auto now = AdmissionClock::now();
    const auto expected = descriptor(ClientVersion::richonline);
    pending.prepare({123, ClientVersion::richonline, expected, now + std::chrono::minutes(1)}, now);
    std::array<std::optional<std::uint64_t>,2> results;
    std::thread a([&] { results[0] = pending.consume(ClientVersion::richonline, expected, now); });
    std::thread b([&] { results[1] = pending.consume(ClientVersion::richonline, expected, now); });
    a.join(); b.join();
    require(results[0].has_value() != results[1].has_value(), "simultaneous_descriptor_consumed_twice");
}
void sent_notifications_require_exact_whole_frames() {
    const auto version=ClientVersion::richonline;
    for(const auto scenario:{0,1,2,3,4}) {
        int sent=0,released=0;
        GameCallbacks callbacks;
        callbacks.authorize_admission=[](const GameAdmission&){return true;};
        callbacks.admitted=[](const GameAdmission&){return std::vector<Frame>{{55,{1}},{56,{2}}};};
        callbacks.sent=[&](const GameAdmission& admitted,const Frame& frame) {
            require(admitted==descriptor(version),"sent_notification_lost_identity");
            require(frame.wire_type==static_cast<std::uint32_t>(55+sent),"sent_notification_frame_order_changed");
            ++sent;
            if(scenario==4) throw CodecError("sent_checkpoint_failure");
        };
        callbacks.disconnected=[&](const GameAdmission&){++released;};
        GameSession session(version,callbacks);
        const auto wire=session.feed(admission_packet(version));
        require(sent==0 && wire.size()==2,"encode_was_counted_as_delivery");
        if(scenario==0) {
            session.sent(wire[0]); session.sent(wire[1]);
            require(sent==2 && session.state()==GameState::admitted,"whole_frame_notification_missing");
            rejects([&]{session.sent(wire[1]);},"game_sent_without_pending_frame");
        } else if(scenario==1) rejects([&]{session.sent(wire[1]);},"game_sent_frame_out_of_order");
        else if(scenario==2) rejects([&]{session.sent(View(wire[0]).first(wire[0].size()-1));},"game_sent_frame_out_of_order");
        else if(scenario==3) {
            session.finish(); require(sent==0,"finish_acknowledged_unsent_frames");
        } else {
            rejects([&]{session.sent(wire[0]);},"sent_checkpoint_failure");
            require(sent==1,"failed_checkpoint_was_not_invoked_once");
            rejects([&]{session.sent(wire[0]);},"game_sent_without_pending_frame");
        }
        session.finish();
        require(released==1 && session.state()==GameState::closed,"sent_failure_cleanup_repeated_or_missing");
        if(scenario==1 || scenario==2) require(sent==0,"invalid_send_advanced_checkpoint");
    }
    GameCallbacks disabled;
    disabled.authorize_admission=[](const GameAdmission&){return true;};
    disabled.admitted=[](const GameAdmission&){return std::vector<Frame>{{55,{1}}};};
    disabled.sent=[](const GameAdmission&,const Frame&){throw CodecError("disabled_observer_called");};
    disabled.sent_enabled=[](const GameAdmission&){return false;};
    GameSession unobserved(version,disabled);
    const auto wire=unobserved.feed(admission_packet(version));
    unobserved.sent(wire[0]); unobserved.finish();
}
}
int main() {
    try {
        sessions_accept_each_version_without_losing_metadata();
        rejected_admission_never_dispatches_gameplay();
        session_rejects_cross_version_replay_and_incomplete_streams();
        pending_descriptors_are_versioned_owned_expiring_and_single_use();
        concurrent_admission_can_only_consume_once();
        sent_notifications_require_exact_whole_frames();
        std::cout << "game session boundary tests PASS\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
