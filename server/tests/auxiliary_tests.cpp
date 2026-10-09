#include "auxiliary.hpp"
#include "codec.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
#include <algorithm>
#include <condition_variable>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace {
using namespace richnet;
void require(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
struct TestNetwork {
    TestNetwork() {
        WSADATA data{};
        require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "test_winsock_start_failed");
    }
    ~TestNetwork() { WSACleanup(); }
};
struct EventCopy {
    std::string event;
    std::string reason;
    AuxiliaryKind service;
    std::optional<std::uint32_t> type;
};
struct Harness {
    std::mutex mutex;
    std::condition_variable changed;
    unsigned listeners = 0;
    std::vector<EventCopy> events;
    std::exception_ptr error;
    AuxiliaryService service;
    std::thread thread;
    explicit Harness(AuxiliaryOptions options) : service(std::move(options), [this](const AuxiliaryEvent& entry) {
        const std::lock_guard lock(mutex);
        if (entry.event == "auxiliary_listening") ++listeners;
        events.push_back({std::string(entry.event), std::string(entry.reason), entry.service, entry.wire_type});
        changed.notify_all();
    }), thread([this] {
        try { service.run(); }
        catch (...) {
            const std::lock_guard lock(mutex);
            error = std::current_exception();
            changed.notify_all();
        }
    }) {}
    ~Harness() { service.stop(); if (thread.joinable()) thread.join(); }
    void await_listening() {
        std::unique_lock lock(mutex);
        require(changed.wait_for(lock, std::chrono::seconds(5), [&] { return listeners == 2 || error; }), "listeners_not_started");
        if (error) std::rethrow_exception(error);
    }
    void await_reason(std::string_view reason) {
        std::unique_lock lock(mutex);
        require(changed.wait_for(lock, std::chrono::seconds(5), [&] {
            return std::any_of(events.begin(), events.end(), [&](const auto& item) { return item.reason == reason; });
        }), "expected_auxiliary_log_missing");
    }
    void await_accept() {
        std::unique_lock lock(mutex);
        require(changed.wait_for(lock, std::chrono::seconds(5), [&] {
            return std::any_of(events.begin(), events.end(), [](const auto& item) { return item.event == "auxiliary_connection_accepted"; });
        }), "auxiliary_peer_not_accepted");
    }
};
struct ClientSocket {
    SOCKET value;
    explicit ClientSocket(SOCKET socket) : value(socket) {}
    ~ClientSocket() { if (value != INVALID_SOCKET) closesocket(value); }
    ClientSocket(const ClientSocket&) = delete;
    ClientSocket& operator=(const ClientSocket&) = delete;
};
std::unique_ptr<ClientSocket> connect_to(std::uint16_t port) {
    auto socket = std::make_unique<ClientSocket>(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    require(socket->value != INVALID_SOCKET, "tcp_client_socket_failed");
    const DWORD timeout = 5000;
    require(::setsockopt(socket->value, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0,
            "tcp_client_timeout_failed");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    require(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1, "tcp_client_address_failed");
    require(::connect(socket->value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0, "tcp_connect_failed");
    return socket;
}
void send_all(SOCKET socket, View bytes) {
    while (!bytes.empty()) {
        const auto count = ::send(socket, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), 0);
        require(count > 0, "tcp_send_failed");
        bytes = bytes.subspan(static_cast<std::size_t>(count));
    }
}
Bytes receive_to_close(SOCKET socket) {
    Bytes result;
    std::array<std::uint8_t, 2048> chunk{};
    while (true) {
        const auto count = ::recv(socket, reinterpret_cast<char*>(chunk.data()), static_cast<int>(chunk.size()), 0);
        if (count < 0) throw std::runtime_error("tcp_receive_failed_" + std::to_string(WSAGetLastError()));
        if (count == 0) return result;
        result.insert(result.end(), chunk.begin(), chunk.begin() + count);
        require(result.size() < 8192, "unexpected_response_size");
    }
}
AuxiliaryOptions options() {
    AuxiliaryOptions result;
    result.http_port = 0;
    result.black_port = 0;
    result.advertised_host = "192.0.2.20";
    result.lobby_port = 24680;
    result.capacity = 137;
    result.channel_id = 0;
    result.current_players = [] { return 3U; };
    result.channels = {
        {0, "初級", 40, 137, 0, 1, 0, 999999999, 0, 999, {}},
        {1, "高級", 50, 147, 2, 1, 0, 999999999, 0, 999, {}},
        {2, "競技", 60, 157, 1, 1, 0, 999999999, 0, 999, {}}
    };
    result.channel_players = [](std::uint32_t key) { return key + 3U; };
    return result;
}
Bytes http_request(std::string_view method, std::string_view path) {
    const auto request = std::string(method) + " " + std::string(path) + " HTTP/1.1\r\nHost: local\r\n\r\n";
    return {request.begin(), request.end()};
}
Bytes black_request(std::uint32_t type) {
    Bytes request{13, 10};
    append_le(request, type, 4);
    append_le(request, type == 1 || type == 2 ? 96U : 64U, 4);
    request.resize(type == 1 || type == 2 ? 106U : 74U, 0xca);
    return request;
}
void http_bootstrap_uses_live_config_over_real_tcp() {
    Harness running(options());
    running.await_listening();
    for (const auto path : {"/gameinfo/RichNetLogin.txt", "/gameinfo/RichNetServer.txt?ignored=1"}) {
        const auto socket = connect_to(running.service.bound_http_port());
        const auto request = http_request("GET", path);
        for (const auto byte : request) send_all(socket->value, View(&byte, 1));
        const auto raw = receive_to_close(socket->value);
        const std::string response(raw.begin(), raw.end());
        require(response.starts_with("HTTP/1.1 200 OK\r\n"), "http_status_wrong");
        const auto body_start = response.find("\r\n\r\n");
        require(body_start != std::string::npos, "http_header_missing");
        const auto body = response.substr(body_start + 4);
        require(response.find("Content-Length: " + std::to_string(body.size()) + "\r\n") != std::string::npos,
                "http_content_length_wrong");
        require(body.find("MaxPlayerNum=137\nNowPlayerNum=3\nIPAddress=192.0.2.20\nPort=24680\n") != std::string::npos,
                "http_configuration_not_used");
        require(body.starts_with("[area]\nareasum=1\n[area0]\nchannelsum=3\n[channel0_0]\n"), "bootstrap_sections_wrong");
        const std::array names{"\xaa\xec\xaf\xc5", "\xb0\xaa\xaf\xc5", "\xc4\x76\xa7\xde"};
        const std::array types{"CHU", "GAO", "ZHONG"};
        for (std::size_t index = 0; index < names.size(); ++index) {
            const auto begin = body.find("[channel0_" + std::to_string(index) + "]\n");
            require(begin != std::string::npos, "catalog_channel_missing");
            const auto end = body.find("[channel0_", begin + 1);
            const auto entry = body.substr(begin, end == std::string::npos ? end : end - begin);
            require(entry.find(std::string("LobbyName=") + names[index] + '\n') != std::string::npos, "big5_channel_name_wrong");
            require(entry.find("NowPlayerNum=" + std::to_string(index + 3) + '\n') != std::string::npos, "channel_population_wrong");
            require(entry.find("ChannelID=" + std::to_string(index) + '\n') != std::string::npos, "channel_key_wrong");
            require(entry.find(std::string("LobbyType=") + types[index] + '\n') != std::string::npos, "lobby_type_token_wrong");
            require(entry.find("LobbyStatus=1\nJDMin=0\nJDMax=999999999\nLvMin=0\nLvMax=999\n") != std::string::npos,
                    "open_test_policy_wrong");
        }
    }
}
void http_rejects_routes_and_methods_without_disk_access() {
    Harness running(options());
    running.await_listening();
    const std::array cases{std::pair{"GET", "/../../Windows/win.ini"}, std::pair{"POST", "/gameinfo/RichNetLogin.txt"}};
    const std::array expected{"HTTP/1.1 404 Not Found\r\n", "HTTP/1.1 405 Method Not Allowed\r\n"};
    for (std::size_t index = 0; index < cases.size(); ++index) {
        const auto socket = connect_to(running.service.bound_http_port());
        send_all(socket->value, http_request(cases[index].first, cases[index].second));
        const auto bytes = receive_to_close(socket->value);
        require(std::string(bytes.begin(), bytes.end()).starts_with(expected[index]), "http_rejection_status_wrong");
    }
}
void blacklist_list_sends_exact_terminator_with_fragmented_request() {
    Harness running(options());
    running.await_listening();
    const auto socket = connect_to(running.service.bound_black_port());
    const auto request = black_request(0);
    for (const auto byte : request) send_all(socket->value, View(&byte, 1));
    Bytes expected{13, 10, 0, 0, 0, 0, 33, 0, 0, 0};
    expected.resize(43, 0);
    require(receive_to_close(socket->value) == expected, "blacklist_terminator_wrong");
    running.await_reason("empty_blacklist_terminator_auth_not_asserted");
}
void blacklist_mutation_closes_without_claiming_success() {
    Harness running(options());
    running.await_listening();
    const auto socket = connect_to(running.service.bound_black_port());
    send_all(socket->value, black_request(1));
    require(receive_to_close(socket->value).empty(), "unsupported_black_operation_sent_success");
    running.await_reason("black_operation_not_implemented");
}
void blacklist_bad_length_closes_and_logs_exact_reason() {
    Harness running(options());
    running.await_listening();
    const auto socket = connect_to(running.service.bound_black_port());
    auto request = black_request(0);
    request[6] = 65;
    send_all(socket->value, request);
    require(receive_to_close(socket->value).empty(), "malformed_black_request_accepted");
    running.await_reason("black_invalid_payload_length");
}
void oversized_http_header_closes_without_response() {
    Harness running(options());
    running.await_listening();
    const auto socket = connect_to(running.service.bound_http_port());
    const Bytes request(8193, 'A');
    send_all(socket->value, request);
    require(receive_to_close(socket->value).empty(), "oversized_http_request_accepted");
    running.await_reason("auxiliary_request_too_large");
}
void stopping_closes_idle_clients_and_joins_run_thread() {
    Harness running(options());
    running.await_listening();
    const auto socket = connect_to(running.service.bound_http_port());
    running.await_accept();
    running.service.stop();
    running.thread.join();
    if (running.error) std::rethrow_exception(running.error);
    require(running.service.bound_http_port() == 0 && running.service.bound_black_port() == 0, "auxiliary_ports_not_reset");
    require(receive_to_close(socket->value).empty(), "idle_connection_survived_shutdown");
}
}

int main() {
    try {
        const TestNetwork network;
        http_bootstrap_uses_live_config_over_real_tcp();
        http_rejects_routes_and_methods_without_disk_access();
        blacklist_list_sends_exact_terminator_with_fragmented_request();
        blacklist_mutation_closes_without_claiming_success();
        blacklist_bad_length_closes_and_logs_exact_reason();
        oversized_http_header_closes_without_response();
        stopping_closes_idle_clients_and_joins_run_thread();
        std::cout << "auxiliary real TCP tests PASS (7 scenarios)\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
