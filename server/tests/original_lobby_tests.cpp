#include "lobby.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
constexpr auto version = ClientVersion::legacy;
constexpr std::uint32_t descriptor = 0x78563412;
const Bytes raw_password{0xc3, 0xdc, 'p', 'w'};
const Frame sentinel{0x1234, {0xde, 0xad, 0xbe, 0xef}};
void require(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
template<class Action> void rejects(Action action, const char* code) {
    try { action(); } catch (const CodecError& error) {
        require(std::string_view(error.what()) == code, "unexpected_error_code");
        return;
    }
    throw std::runtime_error("expected_rejection");
}
LobbyOptions options() { return {"127.0.0.1", 0, local_lobby_handshake(), version}; }
Bytes public_packet() {
    return encode_frame({759, {0x71, 0, 0, 0}}, {Channel::lobby_c2s, std::nullopt, version});
}
Bytes login_payload(std::uint32_t first = descriptor, std::uint32_t second = 132,
                    std::uint32_t third = 0) {
    Bytes payload;
    for (const auto field : {first, second, third}) append_le(payload, field, 4);
    payload.resize(140, 0xca);
    const Bytes gbk_name{0xb2, 0xe2, 0xca, 0xd4, 0};
    std::copy(gbk_name.begin(), gbk_name.end(), payload.begin() + 12);
    std::copy(raw_password.begin(), raw_password.end(), payload.begin() + 76);
    payload[76 + raw_password.size()] = 0;
    append_le(payload, 0xfedcba98, 4);
    return payload;
}
Bytes login_packet(const Bytes& payload) {
    return encode_frame({58, payload}, {Channel::lobby_c2s, 219, version});
}
LobbyCallbacks callbacks(int& authenticated, std::uint32_t expected_descriptor = descriptor) {
    LobbyCallbacks provider;
    provider.verify_credentials = [&authenticated](const std::string& username, View password) {
        require(username == "\xe6\xb5\x8b\xe8\xaf\x95", "gbk_username_not_decoded");
        require(std::equal(password.begin(), password.end(), raw_password.begin(), raw_password.end()),
                "raw_password_changed");
        ++authenticated;
        return true;
    };
    provider.login_responses = [expected_descriptor](const LobbyLogin& login) {
        require(login.unknown_descriptor_u32 == expected_descriptor, "original_descriptor_not_preserved");
        require(login.unknown_tail_u32 == 0xfedcba98, "login_tail_not_preserved");
        return std::vector<Frame>{sentinel};
    };
    provider.authenticated_request = [](const LobbyLogin&, const Frame& frame) {
        require(frame.wire_type == 34 && frame.payload == Bytes({7, 0, 0, 0}), "request_not_decrypted");
        return std::vector<Frame>{sentinel};
    };
    return provider;
}
void coalesced_login_dispatch_and_private_logs() {
    int authenticated = 0;
    std::vector<std::string> logs;
    RichLobbySession session(options(), callbacks(authenticated), [&](const std::string& line) { logs.push_back(line); });
    const Bytes handshake{0x43, 2, 0, 0, 20, 0, 0, 0, 5, 0, 0, 0, 251, 0, 0, 0, 64, 0, 0, 0};
    require(session.start() == handshake, "original_handshake_wrong");
    auto input = public_packet();
    const auto login = login_packet(login_payload());
    const auto request = encode_frame({34, {7, 0, 0, 0}}, {Channel::lobby_c2s, 219, version});
    input.insert(input.end(), login.begin(), login.end());
    input.insert(input.end(), request.begin(), request.end());
    const auto responses = session.feed(input);
    require(authenticated == 1 && session.state() == LobbyState::authenticated && responses.size() == 2,
            "original_login_not_authenticated");
    for (const auto& response : responses) {
        const auto decoded = decode_frame(response, {Channel::lobby_s2c, 219, version});
        require(decoded.wire_type == sentinel.wire_type && decoded.payload == sentinel.payload, "response_wrong");
    }
    const std::vector<std::string> expected{
        "lobby_handshake_sent type=579", "lobby_received type=759 payload_bytes=4",
        "lobby_received type=58 payload_bytes=144", "lobby_authenticated",
        "lobby_encoded type=4660 payload_bytes=4", "lobby_received type=34 payload_bytes=4",
        "lobby_encoded type=4660 payload_bytes=4"};
    require(logs == expected, "metadata_logs_changed_or_credentials_logged");
}
void fragmented_login_accepts_zero_opaque_descriptor() {
    int authenticated = 0;
    RichLobbySession session(options(), callbacks(authenticated, 0));
    static_cast<void>(session.start());
    auto input = public_packet();
    const auto login = login_packet(login_payload(0));
    input.insert(input.end(), login.begin(), login.end());
    for (std::size_t index = 0; index + 1 < input.size(); ++index)
        require(session.feed(View(input).subspan(index, 1)).empty(), "premature_response");
    require(session.feed(View(input).last(1)).size() == 1 && authenticated == 1, "fragmented_login_failed");
}
void rejected_login(const Bytes& payload, LobbyOptions config, const char* error) {
    int authenticated = 0;
    RichLobbySession session(config, callbacks(authenticated));
    static_cast<void>(session.start());
    static_cast<void>(session.feed(public_packet()));
    rejects([&] { static_cast<void>(session.feed(login_packet(payload))); }, error);
    require(session.state() == LobbyState::closed && authenticated == 0, "invalid_login_authenticated");
}
void descriptors_and_encoding_reject_before_authentication() {
    rejected_login(login_payload(descriptor, 131), options(), "unsupported_original_login_descriptor");
    rejected_login(login_payload(descriptor, 132, 1), options(), "unsupported_original_login_descriptor");
    rejected_login(login_payload(0, 0, 0), options(), "unsupported_original_login_descriptor");
    auto richonline = options();
    richonline.version = ClientVersion::richonline;
    rejected_login(login_payload(), richonline, "unsupported_richonline_login_descriptor");
    auto malformed = login_payload();
    malformed[12] = 0x81; malformed[13] = 0;
    rejected_login(malformed, options(), "login_username_invalid_gbk");
    malformed = login_payload();
    std::fill_n(malformed.begin() + 12, 64, 0xca);
    rejected_login(malformed, options(), "login_slot_not_terminated");
}
void authentication_failure_does_not_emit_success() {
    auto provider = LobbyCallbacks{};
    provider.verify_credentials = [](const std::string&, View) { return false; };
    provider.login_responses = [](const LobbyLogin&) -> std::vector<Frame> {
        throw std::runtime_error("success_after_failed_authentication");
    };
    RichLobbySession session(options(), provider);
    static_cast<void>(session.start());
    static_cast<void>(session.feed(public_packet()));
    rejects([&] { static_cast<void>(session.feed(login_packet(login_payload()))); }, "lobby_authentication_failed");
    require(session.state() == LobbyState::closed, "failed_authentication_left_session_open");
}
}
int main() {
    try {
        coalesced_login_dispatch_and_private_logs();
        fragmented_login_accepts_zero_opaque_descriptor();
        descriptors_and_encoding_reject_before_authentication();
        authentication_failure_does_not_emit_success();
        std::cout << "original lobby session tests PASS\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
