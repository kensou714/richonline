#include "lobby_runtime.hpp"
#include "codec.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <chrono>
#include <fstream>
#include <iostream>
#include <thread>

namespace {
using namespace richnet;
using Json = nlohmann::json;
void check(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
struct Network {
    Network() { WSADATA data{}; check(WSAStartup(MAKEWORD(2,2), &data) == 0, "test_winsock_start"); }
    ~Network() { WSACleanup(); }
};
struct Socket {
    SOCKET value;
    explicit Socket(std::uint16_t port) : value(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) {
        check(value != INVALID_SOCKET, "test_socket_create");
        sockaddr_in target{};
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        check(inet_pton(AF_INET, "127.0.0.1", &target.sin_addr) == 1, "test_address");
        if (::connect(value, reinterpret_cast<sockaddr*>(&target), sizeof(target)) != 0) {
            closesocket(value); throw std::runtime_error("test_connect");
        }
        const DWORD timeout = 3000;
        check(setsockopt(value, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0,
              "test_receive_timeout");
    }
    ~Socket() { closesocket(value); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    void send(View bytes) {
        while (!bytes.empty()) {
            const int count = ::send(value, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), 0);
            check(count > 0, "test_send"); bytes = bytes.subspan(static_cast<std::size_t>(count));
        }
    }
    Bytes read(std::size_t size) {
        Bytes data(size);
        std::size_t offset = 0;
        while (offset < size) {
            const int count = ::recv(value, reinterpret_cast<char*>(data.data() + offset), static_cast<int>(size - offset), 0);
            check(count > 0, "test_read"); offset += static_cast<std::size_t>(count);
        }
        return data;
    }
};
std::string http(std::uint16_t port) {
    Socket client(port);
    const std::string request = "GET /gameinfo/RichNetLogin.txt HTTP/1.1\r\nHost: localhost\r\n\r\n";
    client.send({reinterpret_cast<const std::uint8_t*>(request.data()), request.size()});
    std::string response;
    char buffer[1024];
    int count = 0;
    while ((count = recv(client.value, buffer, sizeof(buffer), 0)) > 0) response.append(buffer, static_cast<std::size_t>(count));
    check(count == 0, "test_http_receive");
    return response;
}
Json fixture() {
    Json config{{"provenance", "Synthetic runtime lifecycle test only; opaque test bytes are not production protocol defaults."},
        {"game_capacity", 8}, {"player_capacity", 100}, {"stage_progress", {1,1,2,0}}, {"setting_text", "14"},
        {"network", {{"bind_host", "127.0.0.1"}, {"advertised_host", "127.0.0.1"},
                     {"lobby_port", 0}, {"http_port", 0}, {"black_port", 0}}}};
    for (const auto& [key, size] : std::initializer_list<std::pair<const char*,std::size_t>>{
        {"unknown_channel_record_hex",80},{"unknown_role_record_hex",208},{"unknown_profile_record_hex",272},
        {"unknown_login_result_hex",16},{"unknown_identity_record_hex",16},{"unknown_empty_list_hex",4},
        {"unknown_bank_config_hex",32}}) config[key] = std::string(size * 2, '0');
    config["unknown_completion_hex"] = std::string(40,'0') + "000000000000f03f";
    return config;
}
void write(const std::filesystem::path& path, const Json& value) {
    std::ofstream file(path, std::ios::binary); file << value.dump();
    check(file.good(), "test_fixture_write");
}
void until(const std::function<bool()>& done) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!done()) {
        check(std::chrono::steady_clock::now() < deadline, "test_observation_timeout");
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}
}

int main() {
    try {
        Network network;
        const auto root = std::filesystem::absolute("lobby-runtime-test-" + std::to_string(GetCurrentProcessId()) + "-" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        Storage storage(root / "accounts.sqlite3");
        const auto account = storage.dispatch("accounts.create", {{"username","runtime-test"},{"password","runtime-secret"}}).at("account");
        const auto log = [](const std::string&, const Json&) {};
        LobbyRuntime disabled(storage, root / "missing.json", log);
        check(disabled.status().at("lobbyConfigured") == false, "missing_bootstrap_must_not_listen");
        const auto path = root / "bootstrap.json";
        auto config = fixture(); write(path, config);
        LobbyRuntime runtime(storage, path, log);
        const auto status = runtime.status();
        check(status.at("lobbyReady") == true && status.at("httpReady") == true && status.at("blackReady") == true,
              "runtime_readiness");
        const auto http_port = status.at("httpPort").get<std::uint16_t>();
        const auto lobby_port = status.at("lobbyPort").get<std::uint16_t>();
        check(http(http_port).find("Port=" + std::to_string(lobby_port)) != std::string::npos, "advertised_actual_lobby_port");
        {
            Socket client(lobby_port);
            check(client.read(20).size() == 20, "runtime_handshake");
            client.send(encode_frame({759,{0x71,0,0,0}}, {Channel::lobby_c2s,std::nullopt,ClientVersion::richonline}));
            Bytes payload(144,0);
            const std::string username = "runtime-test", password = "runtime-secret";
            std::copy(username.begin(),username.end(),payload.begin()+12);
            std::copy(password.begin(),password.end(),payload.begin()+76);
            client.send(encode_frame({58,payload}, {Channel::lobby_c2s,219,ClientVersion::richonline}));
            StreamDecoder decoder({Channel::lobby_s2c,219,ClientVersion::richonline});
            const auto responses = decoder.feed(client.read(332));
            check(responses.size() == 3 && responses[0].wire_type == 67, "runtime_sqlite_login");
            check(read_le(View(responses[0].payload).subspan(4,4)) == account.at("role_id").get<std::uint32_t>(),
                  "runtime_database_identity");
            until([&] { return runtime.status().at("authenticatedSessions") == 1; });
            check(http(http_port).find("NowPlayerNum=1") != std::string::npos, "live_session_http_count");
        }
        until([&] { return runtime.status().at("authenticatedSessions") == 0; });
        config["network"]["lobby_port"] = lobby_port; write(root / "collision.json", config);
        bool rejected = false;
        try { LobbyRuntime collision(storage, root / "collision.json", log); }
        catch (const CodecError& error) { rejected = std::string(error.what()).find("lobby_bind_failed") != std::string::npos; }
        check(rejected && runtime.status().at("lobbyReady") == true, "port_collision_preserves_existing_runtime");
        runtime.stop();
        check(runtime.status().at("lobbyReady") == false && runtime.status().at("httpReady") == false &&
              runtime.status().at("blackReady") == false, "all_listeners_stopped");
        std::cout << "PASS native runtime: scoped listeners, HTTP discovery, SQLite TCP login, live counts, collision and clean stop.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
