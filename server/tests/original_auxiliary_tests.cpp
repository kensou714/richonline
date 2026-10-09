#include "auxiliary.hpp"
#include "blacklist_store.hpp"
#include "original_blacklist.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <thread>

namespace {
using namespace richnet;
void require(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
struct Network {
    Network() { WSADATA data{}; require(WSAStartup(MAKEWORD(2,2), &data) == 0, "winsock_start_failed"); }
    ~Network() { WSACleanup(); }
};
struct Socket {
    SOCKET value = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Socket() { require(value != INVALID_SOCKET, "socket_create_failed"); }
    ~Socket() { closesocket(value); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
};
struct TempDatabase {
    std::filesystem::path path = std::filesystem::temp_directory_path() /
        ("original-auxiliary-" + std::to_string(GetCurrentProcessId()) + "-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3");
    ~TempDatabase() { std::error_code error; std::filesystem::remove(path, error); }
};
struct Event {
    std::string name, reason;
    std::optional<std::uint32_t> type;
};
struct Harness {
    std::mutex mutex;
    std::condition_variable changed;
    unsigned listeners = 0;
    bool finished = false;
    std::exception_ptr error;
    std::vector<Event> events;
    AuxiliaryService service;
    std::thread thread;
    explicit Harness(AuxiliaryOptions options) : service(std::move(options), [this](const AuxiliaryEvent& event) {
        const std::lock_guard lock(mutex);
        if (event.event == "auxiliary_listening") ++listeners;
        events.push_back({std::string(event.event), std::string(event.reason), event.wire_type});
        changed.notify_all();
    }), thread([this] {
        try { service.run(); } catch (...) { const std::lock_guard lock(mutex); error = std::current_exception(); }
        const std::lock_guard lock(mutex); finished = true; changed.notify_all();
    }) {}
    ~Harness() {
        service.stop();
        std::unique_lock lock(mutex);
        if (!changed.wait_for(lock, std::chrono::seconds(5), [&] { return finished; })) std::abort();
        lock.unlock(); thread.join();
    }
    void ready() {
        std::unique_lock lock(mutex);
        require(changed.wait_for(lock, std::chrono::seconds(5), [&] { return listeners == 2 || finished; }), "listen_timeout");
        if (error) std::rethrow_exception(error);
        require(listeners == 2, "listeners_missing");
    }
    void logged(std::string_view reason, std::uint32_t type) {
        std::unique_lock lock(mutex);
        require(changed.wait_for(lock, std::chrono::seconds(5), [&] {
            return std::any_of(events.begin(), events.end(), [&](const Event& e) { return e.reason == reason && e.type == type; });
        }), "diagnostic_code_or_wire_type_missing");
    }
};
void connect(Socket& socket, std::uint16_t port) {
    const DWORD timeout = 3000;
    for (const auto option : {SO_RCVTIMEO, SO_SNDTIMEO})
        require(setsockopt(socket.value, SOL_SOCKET, option, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0,
                "socket_timeout_failed");
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(port);
    require(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1, "address_failed");
    require(::connect(socket.value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0, "connect_failed");
}
Bytes transact(std::uint16_t port, View request) {
    Socket socket; connect(socket, port);
    while (!request.empty()) {
        const auto size = std::min<std::size_t>(3, request.size());
        const auto sent = send(socket.value, reinterpret_cast<const char*>(request.data()), static_cast<int>(size), 0);
        require(sent > 0, "fragmented_send_failed"); request = request.subspan(static_cast<std::size_t>(sent));
    }
    Bytes response; std::array<std::uint8_t, 512> buffer{};
    for (;;) {
        const auto size = recv(socket.value, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0);
        require(size >= 0, "receive_failed_or_missing_eof");
        if (size == 0) return response;
        response.insert(response.end(), buffer.begin(), buffer.begin() + size);
        require(response.size() < 8192, "response_too_large");
    }
}
const Bytes owner{'r','o','l','e','_','n','i','c','k','n','a','m','e'};
const Bytes other_owner{'o','t','h','e','r'};
const Bytes digest{'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
                   '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
const Bytes gbk{0xb2,0xe2,0xca,0xd4};
Bytes request(std::uint32_t mode, View account = owner, View key = digest, View target = {}, std::uint8_t enabled = 1) {
    const auto length = mode == 4 ? 97U : mode == 1 || mode == 2 ? 96U : 64U;
    Bytes result{13,10}; append_le(result, mode, 4); append_le(result, length, 4); result.resize(10 + length, 0);
    std::copy(account.begin(), account.end(), result.begin() + 10);
    std::copy(key.begin(), key.end(), result.begin() + 42);
    if (!target.empty()) std::copy(target.begin(), target.end(), result.begin() + 74);
    if (mode == 4) result[106] = enabled;
    return result;
}
void check_list(View response, std::vector<Bytes> expected, View disabled = {}) {
    require(response.size() == (expected.size() + 1) * 43, "list_record_count_wrong");
    std::vector<Bytes> received;
    for (std::size_t index = 0; index <= expected.size(); ++index) {
        const auto record = response.subspan(index * 43, 43);
        require(record[0] == 13 && record[1] == 10 && read_le(record.subspan(2,4)) == 0 &&
                read_le(record.subspan(6,4)) == 33, "list_record_header_wrong");
        const auto name = record.subspan(10,32);
        const auto end = std::find(name.begin(), name.end(), 0);
        if (index == expected.size()) require(name[0] == 0, "list_terminator_missing");
        else {
            const bool enabled = !std::equal(name.begin(), end, disabled.begin(), disabled.end());
            require(end != name.begin() && record[42] == static_cast<std::uint8_t>(enabled), "list_name_or_flag_wrong");
            received.emplace_back(name.begin(), end);
        }
    }
    std::sort(received.begin(), received.end()); std::sort(expected.begin(), expected.end());
    require(received == expected, "list_names_not_preserved");
}
void check_mutation(View response, std::uint32_t mode, View target, bool success = true) {
    require(response.size() == 46 && response[0] == 13 && response[1] == 10 &&
            read_le(response.subspan(2,4)) == mode && read_le(response.subspan(6,4)) == 36, "mutation_header_wrong");
    require((read_le(response.subspan(10,4)) == 0) == success, "mutation_status_wrong");
    if (success) {
        const auto name = response.subspan(14,32);
        require(std::equal(target.begin(), target.end(), name.begin()), "mutation_target_wrong");
        if (target.size() < 32) require(name[target.size()] == 0, "mutation_name_unterminated");
    }
}
AuxiliaryOptions options(BlacklistStore& store, std::atomic_uint32_t& players, std::uint16_t lobby_port) {
    AuxiliaryOptions value; value.http_port = 0; value.black_port = 0;
    value.lobby_port = lobby_port; value.channel_id = 7; value.lobby_type = 0;
    value.current_players = [&players] { return players.load(); };
    value.black_response = [&store](View packet) { return original_blacklist_response(store, packet); };
    return value;
}
void verify_logs(Harness& running) {
    const std::lock_guard lock(running.mutex);
    const std::array secrets{std::string(owner.begin(),owner.end()), std::string(digest.begin(),digest.end())};
    for (const auto& event : running.events)
        for (const auto& secret : secrets)
            require(event.name.find(secret) == std::string::npos && event.reason.find(secret) == std::string::npos,
                    "credentials_leaked_in_log");
}
void blacklist_persistence_and_rejections(std::uint16_t lobby_port) {
    TempDatabase temporary; std::atomic_uint32_t players{0};
    Bytes full_name; for (unsigned index = 0; index < 16; ++index) full_name.insert(full_name.end(), {0xd6,0xd0});
    auto other_digest = digest; other_digest[0] = 'f';
    {
        BlacklistStore store(temporary.path); Harness running(options(store, players, lobby_port)); running.ready();
        const auto port = running.service.bound_black_port();
        check_list(transact(port, request(0)), {});
        for (const auto& name : {gbk, full_name, gbk}) check_mutation(transact(port, request(1, owner, digest, name)), 1, name);
        check_list(transact(port, request(0)), {gbk,full_name});
        check_list(transact(port, request(0,other_owner)), {});
        check_list(transact(port, request(0,owner,other_digest)), {});
        check_mutation(transact(port, request(2,other_owner,digest,gbk)), 2, gbk, false);
        check_mutation(transact(port, request(2,owner,other_digest,gbk)), 2, gbk, false);
        check_list(transact(port, request(0)), {gbk,full_name});
        require(transact(port,request(4,owner,digest,full_name,0)).empty(), "mode4_invented_response");
        check_list(transact(port,request(0)), {gbk,full_name}, full_name);
        check_mutation(transact(port,request(1,owner,digest,full_name)),1,full_name);
        check_list(transact(port,request(0)), {gbk,full_name}, full_name);
        auto invalid_length = request(0); invalid_length.resize(10); invalid_length[6] = 65;
        auto unknown_mode = request(99); unknown_mode.resize(10);
        auto invalid_digest = request(0); invalid_digest[42] = 'G';
        const std::array bad{invalid_length, unknown_mode, invalid_digest, request(3),
            request(4,owner,digest,full_name,2), request(4,other_owner,digest,full_name), request(4,owner,other_digest,full_name)};
        const std::array codes{"black_invalid_payload_length","black_type_unsupported","black_digest_invalid","black_mode3_semantics_unverified",
            "black_enabled_flag_invalid","black_flag_target_missing","black_flag_target_missing"};
        for (std::size_t index = 0; index < bad.size(); ++index) {
            require(transact(port,bad[index]).empty(), "invalid_request_returned_success");
            running.logged(codes[index], static_cast<std::uint32_t>(read_le(View(bad[index]).subspan(2,4))));
            check_list(transact(port,request(0)), {gbk,full_name}, full_name);
        }
        running.logged("original_blacklist_completed",1); verify_logs(running);
    }
    {
        BlacklistStore reopened(temporary.path); Harness running(options(reopened, players, lobby_port)); running.ready();
        const auto port = running.service.bound_black_port(); check_list(transact(port,request(0)), {gbk,full_name}, full_name);
        require(transact(port,request(4,owner,digest,full_name,1)).empty(), "mode4_enable_invented_response");
        check_list(transact(port,request(0)), {gbk,full_name});
        check_mutation(transact(port,request(2,owner,digest,gbk)),2,gbk);
        check_mutation(transact(port,request(2,owner,digest,gbk)),2,gbk,false);
        check_list(transact(port,request(0)), {full_name});
        running.logged("original_blacklist_completed",2); verify_logs(running);
    }
}
void discovery_uses_bound_lobby_and_live_players(std::uint16_t lobby_port) {
    TempDatabase temporary; BlacklistStore store(temporary.path); std::atomic_uint32_t players{2};
    Harness running(options(store,players,lobby_port)); running.ready();
    for (const auto path : {"/gameinfo/RichNetLogin.txt", "/gameinfo/RichNetServer.txt?cache=1"}) {
        const auto text = std::string("GET ") + path + " HTTP/1.1\r\nHost: localhost\r\n\r\n";
        const Bytes query(text.begin(),text.end()); const auto raw = transact(running.service.bound_http_port(),query);
        const std::string response(raw.begin(),raw.end()); const auto separator = response.find("\r\n\r\n");
        require(response.starts_with("HTTP/1.1 200 OK\r\n") && separator != std::string::npos,"http_discovery_failed");
        const auto body = response.substr(separator+4);
        require(response.find("Content-Length: " + std::to_string(body.size()) + "\r\n") != std::string::npos,"http_length_wrong");
        for (const auto& field : {"\nLobbyType=0\n", "\nChannelID=7\n"}) require(body.find(field) != std::string::npos,"original_channel_field_wrong");
        require(body.find("\nPort=" + std::to_string(lobby_port) + "\n") != std::string::npos,"bound_lobby_port_wrong");
        require(body.find("\nNowPlayerNum=" + std::to_string(players.load()) + "\n") != std::string::npos,"live_players_wrong");
        players.store(5);
    }
}
}
int main() {
    try {
        const Network network; Socket lobby;
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        require(bind(lobby.value,reinterpret_cast<const sockaddr*>(&address),sizeof(address)) == 0,"lobby_bind_failed");
        require(listen(lobby.value,1) == 0,"lobby_listen_failed"); int size = sizeof(address);
        require(getsockname(lobby.value,reinterpret_cast<sockaddr*>(&address),&size) == 0,"lobby_port_failed");
        blacklist_persistence_and_rejections(ntohs(address.sin_port));
        discovery_uses_bound_lobby_and_live_players(ntohs(address.sin_port));
        std::cout << "original auxiliary real TCP PASS: GBK, persistence, isolation, EOF, diagnostics, live discovery\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return EXIT_FAILURE; }
}
