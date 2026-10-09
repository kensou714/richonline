#include "lobby.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <string_view>
#include <thread>

namespace {
using namespace richnet;
void require(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
template<class Action> void rejects(Action action, const char* code) {
    try { action(); } catch (const CodecError& error) {
        require(std::string_view(error.what()) == code, "unexpected_error_code");
        return;
    }
    throw std::runtime_error("expected_rejection");
}
LobbyOptions options() { return {"127.0.0.1", 0, local_lobby_handshake()}; }
Bytes public_packet() {
    return encode_frame({759, {0x71, 0, 0, 0}}, {Channel::lobby_c2s, std::nullopt, ClientVersion::richonline});
}
Bytes login_packet(std::uint8_t descriptor = 0) {
    Bytes payload(144, 0xca);
    std::fill_n(payload.begin(), 12, 0);
    payload[0] = descriptor;
    const Bytes name{0xb4, 0xfa, 0xb8, 0xd5, 0};
    std::copy(name.begin(), name.end(), payload.begin() + 12);
    const Bytes password{'s', 'e', 'c', 'r', 'e', 't', 0};
    std::copy(password.begin(), password.end(), payload.begin() + 76);
    payload[140] = 0x12; payload[141] = 0x34; payload[142] = 0x56; payload[143] = 0x78;
    return encode_frame({58, payload}, {Channel::lobby_c2s, 219, ClientVersion::richonline});
}
LobbyCallbacks callbacks(int& authenticated) {
    LobbyCallbacks result;
    result.verify_credentials = [&authenticated](const std::string& username, View password) {
        require(username == "\xe6\xb8\xac\xe8\xa9\xa6", "big5_username_not_decoded");
        const Bytes expected{'s', 'e', 'c', 'r', 'e', 't'};
        require(std::equal(password.begin(), password.end(), expected.begin(), expected.end()), "password_slot_wrong");
        ++authenticated;
        return true;
    };
    result.login_responses = [](const LobbyLogin& login) {
        require(login.unknown_tail_u32 == 0x78563412, "unknown_login_tail_lost");
        return std::vector<Frame>{{1, {0x12, 0x34, 0x56, 0x78, 1, 0, 0, 0}}};
    };
    result.authenticated_request = [](const LobbyLogin&, const Frame& frame) {
        require(frame.wire_type == 34 && frame.payload == Bytes({7, 0, 0, 0}), "request_not_decrypted");
        return std::vector<Frame>{{9, {2, 0, 0, 0, 7, 0, 0, 0}}};
    };
    return result;
}

void handshake_has_explicit_policy() {
    RichLobbySession disabled({}, {});
    rejects([&] { static_cast<void>(disabled.start()); }, "lobby_handshake_not_configured");
    RichLobbySession enabled(options(), {});
    const Bytes expected{0x43, 2, 0, 0, 20, 0, 0, 0, 5, 0, 0, 0, 251, 0, 0, 0, 64, 0, 0, 0};
    require(enabled.start() == expected, "handshake_layout_wrong");
}
void coalesced_handshake_and_login_switch_key_at_boundary() {
    int authenticated = 0;
    std::string logs;
    RichLobbySession session(options(), callbacks(authenticated), [&](const std::string& line) { logs += line; });
    static_cast<void>(session.start());
    auto input = public_packet();
    const auto login = login_packet();
    input.insert(input.end(), login.begin(), login.end());
    const auto responses = session.feed(input);
    require(authenticated == 1 && session.state() == LobbyState::authenticated, "login_not_authenticated");
    require(responses.size() == 1, "login_response_count_wrong");
    const auto decoded = decode_frame(responses[0], {Channel::lobby_s2c, 219, ClientVersion::richonline});
    require(decoded.wire_type == 1 && decoded.payload == Bytes({0x12, 0x34, 0x56, 0x78, 1, 0, 0, 0}), "login_response_wrong");
    require(logs.find("secret") == std::string::npos, "credentials_logged");
    const auto request = encode_frame({34, {7, 0, 0, 0}}, {Channel::lobby_c2s, 219, ClientVersion::richonline});
    const auto followup = session.feed(request);
    require(followup.size() == 1, "authenticated_request_not_dispatched");
}
void byte_fragmented_login_preserves_padding_and_state() {
    int authenticated = 0;
    RichLobbySession session(options(), callbacks(authenticated));
    static_cast<void>(session.start());
    const auto public_frame = public_packet();
    for (const auto byte : public_frame) require(session.feed(View(&byte, 1)).empty(), "public_response_unexpected");
    auto packet = login_packet();
    for (std::size_t i = 0; i + 1 < packet.size(); ++i)
        require(session.feed(View(packet).subspan(i, 1)).empty(), "premature_login_response");
    require(session.feed(View(packet).last(1)).size() == 1, "fragmented_login_failed");
}
void malformed_input_closes_session() {
    int authenticated = 0;
    RichLobbySession descriptor(options(), callbacks(authenticated));
    static_cast<void>(descriptor.start());
    static_cast<void>(descriptor.feed(public_packet()));
    rejects([&] { static_cast<void>(descriptor.feed(login_packet(1))); }, "unsupported_richonline_login_descriptor");
    require(descriptor.state() == LobbyState::closed && authenticated == 0, "invalid_descriptor_accepted");
    RichLobbySession magic_session(options(), {});
    static_cast<void>(magic_session.start());
    auto bad_magic = public_packet(); bad_magic[0] = 0;
    rejects([&] { static_cast<void>(magic_session.feed(bad_magic)); }, "invalid_lobby_magic");
    RichLobbySession truncated(options(), {});
    static_cast<void>(truncated.start());
    static_cast<void>(truncated.feed(View(public_packet()).first(7)));
    rejects([&] { truncated.finish(); }, "truncated_lobby_stream");
}
void failed_credentials_do_not_send_success() {
    LobbyCallbacks provider;
    provider.verify_credentials = [](const std::string&, View) { return false; };
    provider.login_responses = [](const LobbyLogin&) -> std::vector<Frame> {
        throw std::runtime_error("success_provider_called_after_failure");
    };
    RichLobbySession session(options(), provider);
    static_cast<void>(session.start());
    static_cast<void>(session.feed(public_packet()));
    const auto responses = session.feed(login_packet());
    require(responses.size() == 1 && session.state() == LobbyState::closed, "failed_authentication_lifecycle_wrong");
    const auto failure = decode_frame(responses.front(), {Channel::lobby_s2c, 219, ClientVersion::richonline});
    require(failure.wire_type == 0xffffffffU && failure.payload == Bytes{58,0,0,0,0x9b,0xff,0xff,0xff,0},
        "failed_authentication_response_wrong");
}
#ifdef _WIN32
struct ClientSocket {
    SOCKET value;
    ~ClientSocket() { closesocket(value); }
};
struct RunningService {
    RichLobbyService& service;
    std::exception_ptr error;
    std::thread thread;
    explicit RunningService(RichLobbyService& target) : service(target), thread([this] {
        try { service.run(); } catch (...) { error = std::current_exception(); }
    }) {}
    ~RunningService() { service.stop(); if (thread.joinable()) thread.join(); }
};
void send_all(SOCKET socket, View bytes) {
    while (!bytes.empty()) {
        const auto count = ::send(socket, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), 0);
        require(count > 0, "tcp_send_failed");
        bytes = bytes.subspan(static_cast<std::size_t>(count));
    }
}
Bytes read_all(SOCKET socket, std::size_t size) {
    Bytes bytes(size);
    std::size_t position = 0;
    while (position < size) {
        const auto count = ::recv(socket, reinterpret_cast<char*>(bytes.data() + position), static_cast<int>(size - position), 0);
        require(count > 0, "tcp_receive_failed");
        position += static_cast<std::size_t>(count);
    }
    return bytes;
}
void tcp_service_authenticates_and_dispatches_real_frames() {
    std::mutex mutex;
    std::condition_variable started;
    bool listening = false;
    int authenticated = 0;
    RichLobbyService service(options(), callbacks(authenticated), [&](const std::string& line) {
        if (line.find("lobby_listening ") == 0) {
            const std::lock_guard lock(mutex);
            listening = true;
            started.notify_one();
        }
    });
    RunningService running(service);
    {
        std::unique_lock lock(mutex);
        require(started.wait_for(lock, std::chrono::seconds(5), [&] { return listening; }), "tcp_listener_not_started");
    }
    const ClientSocket socket{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    require(socket.value != INVALID_SOCKET, "tcp_client_socket_failed");
    const DWORD timeout = 5000;
    require(::setsockopt(socket.value, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0,
            "tcp_timeout_failed");
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(service.bound_port());
    require(inet_pton(AF_INET, "127.0.0.1", &target.sin_addr) == 1, "tcp_address_failed");
    require(::connect(socket.value, reinterpret_cast<sockaddr*>(&target), sizeof(target)) == 0, "tcp_connect_failed");
    const auto handshake = read_all(socket.value, 20);
    require(handshake == Bytes({0x43, 2, 0, 0, 20, 0, 0, 0, 5, 0, 0, 0, 251, 0, 0, 0, 64, 0, 0, 0}), "tcp_handshake_wrong");
    auto input = public_packet();
    const auto login = login_packet();
    const auto channel = encode_frame({34, {7, 0, 0, 0}}, {Channel::lobby_c2s, 219, ClientVersion::richonline});
    input.insert(input.end(), login.begin(), login.end());
    input.insert(input.end(), channel.begin(), channel.end());
    send_all(socket.value, input);
    const auto output = read_all(socket.value, 32);
    StreamDecoder decoder({Channel::lobby_s2c, 219, ClientVersion::richonline});
    const auto responses = decoder.feed(output);
    decoder.finish();
    require(responses.size() == 2 && responses[0].wire_type == 1 && responses[1].wire_type == 9,
            "tcp_responses_wrong");
    require(responses[1].payload == Bytes({2, 0, 0, 0, 7, 0, 0, 0}), "tcp_channel_payload_wrong");
    service.stop();
    running.thread.join();
    if (running.error) std::rethrow_exception(running.error);
    require(authenticated == 1 && service.bound_port() == 0, "tcp_shutdown_or_authentication_wrong");
}
#endif
}
int main() {
    try {
        handshake_has_explicit_policy();
        coalesced_handshake_and_login_switch_key_at_boundary();
        byte_fragmented_login_preserves_padding_and_state();
        malformed_input_closes_session();
        failed_credentials_do_not_send_success();
#ifdef _WIN32
        tcp_service_authenticates_and_dispatches_real_frames();
#endif
        std::cout << "lobby state machine tests PASS\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
