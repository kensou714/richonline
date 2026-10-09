#include "original_lobby_adapter.hpp"
#include "original_room_description.hpp"
#include "original_bank_fixture.hpp"
#include "original_exchange_test_scenario.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>

namespace {
using namespace richnet;
using Json = nlohmann::json;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
Bytes words(std::initializer_list<std::uint32_t> values) { Bytes data; for (const auto value : values) append_le(data,value,4); return data; }
std::uint32_t u32(const Bytes& data, std::size_t offset) { return read_le(View(data).subspan(offset,4)); }
void put(Bytes& data, std::size_t offset, std::uint32_t value) {
    for (std::size_t i=0;i<4;++i) data.at(offset+i) = static_cast<std::uint8_t>(value >> (8*i));
}
struct Scratch {
    std::filesystem::path path;
    Scratch() {
        for (std::uint32_t i=1;i<10000;++i) {
            path = std::filesystem::temp_directory_path()/L"original-room-service-tests"/std::to_wstring(i);
            if (std::filesystem::create_directories(path)) return;
        }
        throw std::runtime_error("scratch_exhausted");
    }
    ~Scratch() { std::error_code ignored; std::filesystem::remove_all(path,ignored); }
};
struct Winsock {
    Winsock() { WSADATA data{}; check(WSAStartup(MAKEWORD(2,2),&data) == 0,"winsock_failed"); }
    ~Winsock() { WSACleanup(); }
};
struct Client {
    SOCKET socket = ::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    std::uint32_t user = 0;
    explicit Client(std::uint16_t port) {
        check(socket != INVALID_SOCKET,"socket_failed");
        try {
            const DWORD timeout = 5000;
            for (const auto option : {SO_RCVTIMEO,SO_SNDTIMEO})
                check(setsockopt(socket,SOL_SOCKET,option,reinterpret_cast<const char*>(&timeout),sizeof(timeout)) == 0,"socket_timeout_failed");
            sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(port);
            check(inet_pton(AF_INET,"127.0.0.1",&address.sin_addr) == 1,"socket_address_failed");
            check(connect(socket,reinterpret_cast<sockaddr*>(&address),sizeof(address)) == 0,"connect_failed");
            check(read(20) == Bytes({0x43,2,0,0,20,0,0,0,5,0,0,0,251,0,0,0,64,0,0,0}),"original_handshake_wrong");
        } catch (...) { closesocket(socket); throw; }
    }
    ~Client() { if (socket != INVALID_SOCKET) closesocket(socket); }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    void close() { check(closesocket(socket) == 0,"close_failed"); socket = INVALID_SOCKET; }
    Bytes read(std::size_t size) {
        Bytes data(size);
        for (std::size_t offset=0;offset<size;) {
            const auto count = recv(socket,reinterpret_cast<char*>(data.data()+offset),static_cast<int>(size-offset),0);
            check(count > 0,"receive_closed_or_timeout"); offset += static_cast<std::size_t>(count);
        }
        return data;
    }
    void send(const Frame& frame, std::optional<std::int32_t> key = 219) {
        const auto data = encode_frame(frame,{Channel::lobby_c2s,key,ClientVersion::legacy});
        for (std::size_t offset=0;offset<data.size();) {
            const auto count = ::send(socket,reinterpret_cast<const char*>(data.data()+offset),static_cast<int>(data.size()-offset),0);
            check(count > 0,"send_failed"); offset += static_cast<std::size_t>(count);
        }
    }
    Frame receive(std::uint32_t type) {
        auto data = read(8); const auto size = u32(data,4);
        check(size >= 8 && size <= max_frame_total,"frame_size_invalid");
        const auto payload = read(size-8); data.insert(data.end(),payload.begin(),payload.end());
        auto frame = decode_frame(data,{Channel::lobby_s2c,219,ClientVersion::legacy});
        if (frame.wire_type != type) throw std::runtime_error("unexpected_frame expected="+std::to_string(type)+" actual="+std::to_string(frame.wire_type));
        return frame;
    }
    void expect(std::uint32_t type, const Bytes& payload) { check(receive(type).payload == payload,"frame_payload_wrong"); }
    void enter(const Json& account) {
        user = account.at("role_id").get<std::uint32_t>();
        send({759,words({113})},std::nullopt);
        Bytes login = words({0x12345678,132,0}); login.resize(144,0xca);
        const auto username = client_text(account.at("username").get<std::string>(),ClientProfile::original);
        constexpr std::string_view password = "room-test-password";
        std::copy(username.begin(),username.end(),login.begin()+12); login[12+username.size()] = 0;
        std::copy(password.begin(),password.end(),login.begin()+76); login[76+password.size()] = 0;
        send({58,std::move(login)});
        const auto catalog = receive(67); check(catalog.payload.size() == 212 && u32(catalog.payload,4) == user,"catalog_wrong");
        check(u32(receive(1).payload,0) == user,"identity_wrong"); send({34,words({user})});
        for (const auto type : {3U,9U,7U,140U,4U,2U,100U,103U,106U,30U}) {
            const auto reply = receive(type);
            if (type == 7) check(reply.payload.size() == 268 && u32(reply.payload,0) == user && u32(reply.payload,12) == 0xffffffffU,"bootstrap_profile_wrong");
        }
    }
    void reject(const Frame& request, std::uint32_t model) {
        send(request); const auto failure = receive(0xffffffffU);
        check(failure.payload.size() == 136 && u32(failure.payload,0) == request.wire_type && u32(failure.payload,4) == 0xffffffffU,"business_error_wrong");
        check(std::all_of(failure.payload.begin()+8,failure.payload.end(),[](auto byte) { return byte == 0; }),"business_error_context_wrong");
        send({10,words({99})}); expect(18,words({user,model}));
    }
};
struct RunningService {
    RichLobbyService& service; std::exception_ptr error; std::thread thread;
    explicit RunningService(RichLobbyService& target) : service(target),thread([this] { try { service.run(); } catch (...) { error = std::current_exception(); } }) {}
    void join() { service.stop(); if (thread.joinable()) thread.join(); }
    ~RunningService() { join(); }
};
Bytes description(bool second = false) {
    Bytes config(208,0xab); config[0] = 'B'; config[1] = 0;
    put(config,32,0x40); put(config,40,1); put(config,44,2); put(config,120,80);
    const std::string_view name = second ? "BS_1_2" : "BS_1_1";
    std::copy(name.begin(),name.end(),config.begin()+128); config[128+name.size()] = 0;
    constexpr std::array<std::uint8_t,16> first{0x77,0x2a,0x81,0xa7,0x87,0x67,0x85,0x52,0x15,0x57,0x8e,0xcf,0xf3,0x9c,0x3a,0xbe};
    constexpr std::array<std::uint8_t,16> next{0xf2,0x6c,0x70,0x77,0x45,0x80,0xc7,0xfe,0x30,0xa6,0xcb,0x16,0xb1,0xaf,0xad,0x60};
    const auto& signature = second ? next : first; std::copy(signature.begin(),signature.end(),config.begin()+160);
    put(config,176,3); return config;
}
Bytes configured(const Bytes& input, std::uint32_t owner) {
    auto config = input; put(config,60,owner); put(config,64,0); put(config,124,0); return config;
}
Bytes prefix(Bytes head, const Bytes& tail) { head.insert(head.end(),tail.begin(),tail.end()); return head; }
void profile(Client& recipient, std::uint32_t user, std::uint32_t team) {
    const auto frame = recipient.receive(7);
    check(frame.payload.size() == 268 && u32(frame.payload,0) == user && u32(frame.payload,12) == 0 && u32(frame.payload,44) == team,"room_profile_wrong");
}
void snapshot(Client& recipient, const Bytes& config, std::uint32_t owner) {
    profile(recipient,owner,0); recipient.expect(5,prefix(words({0,0}),config));
    recipient.expect(40,words({0})); recipient.expect(41,words({1,owner}));
}
void multiplayer_room_roundtrip() {
    const Winsock network; const Scratch scratch;
    Storage storage(scratch.path/L"accounts.sqlite3",ClientProfile::original);
    const auto account = [&](const char* username) { return storage.dispatch("accounts.create",{{"username",username},{"password","room-test-password"}}).at("account"); };
    const auto first = account("room-a"), third = account("room-c");
    auto second = account("room-b");
    second = storage.dispatch("accounts.update",{{"role_id",second.at("role_id")},{"expected",{{"coins",second.at("coins")}}},
        {"changes",{{"coins",12.5}}},{"reason","native room exchange membership fixture"}}).at("account");
    OriginalLobbyPolicy policy{"Test-only opaque templates for three-client native TCP room validation.",
        Bytes(220,0xa1),Bytes(208,0xb2),Bytes(268,0xc3),Bytes(16,0xd4),Bytes(16,0xe5),
        Bytes(original_bank_test::config.begin(),original_bank_test::config.end()),Bytes(28,0x27),3,1,100,32,2,{1,1,2,0},"4096",14,10};
    constexpr std::u8string_view source = RICHONLINE_LEGACY_RESOURCE_ROOT;
    const auto root = std::filesystem::path(std::u8string(source.begin(),source.end()));
    policy.maps = std::make_shared<OriginalMapCatalog>(OriginalMapCatalog::load(root/"protocol-analysis"/"board-startup"/"maps"/"index.json"));
    std::mutex mutex; std::condition_variable changed; bool listening = false; bool runtime_rejected = false;
    const auto log = [&](const std::string& line) {
        const std::lock_guard lock(mutex);
        if (line.starts_with("lobby_listening ")) listening = true;
        if (line.find("reason=game_runtime_not_configured") != std::string::npos) runtime_rejected = true;
        changed.notify_all();
    };
    RichLobbyService service({"127.0.0.1",0,local_lobby_handshake(),ClientVersion::legacy},make_original_lobby_factory(storage,policy,log),log);
    RunningService running(service);
    { std::unique_lock lock(mutex); check(changed.wait_for(lock,std::chrono::seconds(5),[&] { return listening; }),"listener_timeout"); }
    Client a(service.bound_port()), b(service.bound_port()); a.enter(first); b.enter(second);
    const auto initial = description(), canonical = configured(initial,a.user);
    a.send({3,initial}); a.expect(10,prefix(words({0,a.user}),canonical)); snapshot(b,canonical,a.user);
    Client c(service.bound_port()); c.enter(third); snapshot(c,canonical,a.user);
    b.send({4,words({0,3,1})}); profile(a,b.user,3); profile(c,b.user,3);
    for (auto* peer : {&a,&b,&c}) peer->expect(12,words({b.user,0,3,1}));
    b.send({10,words({2})}); for (auto* peer : {&a,&b,&c}) peer->expect(18,words({b.user,2}));
    check(storage.roles_for_username("room-b").at(0).at("model") == 2,"model_not_persisted");
    b.send({9,words({2})}); for (auto* peer : {&a,&b,&c}) peer->expect(17,words({b.user,2}));
    b.send(original_exchange_test::request(2));
    b.expect(79,prefix(prefix(words({1,0}),original_exchange_test::number(2)),original_exchange_test::number(20)));
    const auto refreshed = b.receive(23);
    check(refreshed.payload.size() == 268 && u32(refreshed.payload,0) == b.user && u32(refreshed.payload,12) == 0 &&
        u32(refreshed.payload,44) == 2 && u32(refreshed.payload,40) == 2,"exchange_reset_room_team_or_model");
    original_exchange_test::balance(refreshed.payload,76,10.5);
    original_exchange_test::balance(refreshed.payload,84,second.at("gold").get<double>()+20);
    auto wrong_signature = initial; wrong_signature[160] ^= 1;
    c.reject({3,wrong_signature},third.at("model").get<std::uint32_t>());
    c.reject({3,initial},third.at("model").get<std::uint32_t>());
    c.reject({4,words({0,0,1})},third.at("model").get<std::uint32_t>());
    a.reject({3,initial},first.at("model").get<std::uint32_t>());
    b.reject({23,prefix(words({0}),description(true))},2);
    a.reject({23,prefix(words({0}),wrong_signature)},first.at("model").get<std::uint32_t>());
    b.send({5,{}}); for (auto* peer : {&a,&b,&c}) peer->expect(13,words({b.user,0}));
    b.send({5,{}}); b.send({5,{}});
    b.send({10,words({4})}); b.expect(18,words({b.user,2}));
    b.send({9,words({3})}); b.expect(17,words({b.user,2}));
    const auto next = description(true); a.send({23,prefix(words({0}),next)});
    for (auto* peer : {&a,&b,&c}) { peer->expect(96,words({b.user,0})); peer->expect(26,prefix(words({0}),configured(next,a.user))); }
    b.send({5,{}}); for (auto* peer : {&a,&b,&c}) peer->expect(13,words({b.user,0}));
    a.send({5,{}});
    for (auto* peer : {&a,&b,&c}) { peer->expect(13,words({a.user,0})); peer->expect(96,words({b.user,0})); peer->expect(96,words({a.user,0})); }
    b.send({5,{}}); for (auto* peer : {&a,&b,&c}) peer->expect(13,words({b.user,0}));
    b.send({60,{}}); for (auto* peer : {&a,&b,&c}) peer->expect(96,words({b.user,0}));
    b.send({60,{}}); b.send({60,{}});
    b.send({9,words({2})}); for (auto* peer : {&a,&b,&c}) peer->expect(17,words({b.user,2}));
    a.close(); for (auto* peer : {&b,&c}) peer->expect(14,words({a.user,0,b.user}));
    b.send({6,words({0})}); for (auto* peer : {&b,&c}) peer->expect(14,words({b.user,0,0xffffffffU}));
    c.send({3,initial}); c.expect(10,prefix(words({0,c.user}),configured(initial,c.user))); snapshot(b,configured(initial,c.user),c.user);
    running.join(); if (running.error) std::rethrow_exception(running.error);
    check(runtime_rejected,"full_ready_reason_not_logged");
    Storage reopened(scratch.path/L"accounts.sqlite3",ClientProfile::original);
    check(reopened.roles_for_username("room-b").at(0).at("model") == 2,"model_reopen_mismatch");
}
}
int main() {
    try { multiplayer_room_roundtrip(); std::cout << "PASS original encrypted three-client room create/join/map/model/broadcast/rejection/disconnect lifecycle.\n"; return 0; }
    catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
