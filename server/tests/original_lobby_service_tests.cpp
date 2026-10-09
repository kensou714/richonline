#include "original_lobby_adapter.hpp"
#include "original_bank_fixture.hpp"
#include "original_exchange_test_scenario.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <algorithm>
#include <atomic>
#include <bit>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <limits>
#include <thread>

namespace {
using namespace richnet;
using Json = nlohmann::json;
void require(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
Bytes id_bytes(std::uint32_t id) { Bytes bytes; append_le(bytes,id,4); return bytes; }
std::uint32_t u32(const Bytes& bytes,std::size_t offset) { return read_le(View(bytes).subspan(offset,4)); }
Bytes amount_bytes(double amount) {
    Bytes bytes;
    const auto bits = std::bit_cast<std::uint64_t>(amount);
    for (std::size_t i=0;i<8;++i) bytes.push_back(static_cast<std::uint8_t>(bits >> (8*i)));
    return bytes;
}
OriginalLobbyPolicy policy() {
    return {"Test-only nonzero opaque templates; no historical packet claim.",
        Bytes(220,0xa1),Bytes(208,0xb2),Bytes(268,0xc3),Bytes(16,0xd4),Bytes(16,0xe5),Bytes(original_bank_test::config.begin(),original_bank_test::config.end()),Bytes(28,0x27),
        3,8,100,32,2,{1,1,2,0},"4096",14,10};
}
struct Scratch {
    std::filesystem::path path;
    Scratch() {
        const auto root = std::filesystem::temp_directory_path() / L"original-lobby-service-tests";
        for (std::uint32_t i=1;i<10000;++i) {
            path = root / std::to_wstring(i);
            if (std::filesystem::create_directories(path)) return;
        }
        throw std::runtime_error("scratch_exhausted");
    }
    ~Scratch() { std::error_code error; std::filesystem::remove_all(path,error); }
};
#ifdef _WIN32
struct Winsock {
    Winsock() { WSADATA data{}; require(WSAStartup(MAKEWORD(2,2),&data) == 0,"winsock_start_failed"); }
    ~Winsock() { WSACleanup(); }
};
struct Client {
    SOCKET socket = ::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    explicit Client(std::uint16_t port,bool expect_handshake = true) {
        require(socket != INVALID_SOCKET,"tcp_socket_failed");
        try {
            const DWORD timeout = 5000;
            for (const auto option : {SO_RCVTIMEO,SO_SNDTIMEO})
                require(::setsockopt(socket,SOL_SOCKET,option,reinterpret_cast<const char*>(&timeout),sizeof(timeout)) == 0,
                        "tcp_timeout_failed");
            sockaddr_in address{};
            address.sin_family = AF_INET; address.sin_port = htons(port);
            require(inet_pton(AF_INET,"127.0.0.1",&address.sin_addr) == 1,"tcp_address_failed");
            require(::connect(socket,reinterpret_cast<sockaddr*>(&address),sizeof(address)) == 0,"tcp_connect_failed");
            if (expect_handshake)
                require(read(20) == Bytes({0x43,2,0,0,20,0,0,0,5,0,0,0,251,0,0,0,64,0,0,0}),"original_handshake_wrong");
        } catch (...) { closesocket(socket); throw; }
    }
    ~Client() { closesocket(socket); }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Bytes read(std::size_t size) {
        Bytes bytes(size);
        for (std::size_t offset=0;offset<size;) {
            const auto count = ::recv(socket,reinterpret_cast<char*>(bytes.data()+offset),static_cast<int>(size-offset),0);
            require(count > 0,"tcp_receive_failed_or_timed_out");
            offset += static_cast<std::size_t>(count);
        }
        return bytes;
    }
    void send(const Frame& frame,std::optional<std::int32_t> key = 219) {
        const auto bytes = encode_frame(frame,{Channel::lobby_c2s,key,ClientVersion::legacy});
        for (std::size_t offset=0;offset<bytes.size();) {
            const auto count = ::send(socket,reinterpret_cast<const char*>(bytes.data()+offset),static_cast<int>(bytes.size()-offset),0);
            require(count > 0,"tcp_send_failed_or_timed_out");
            offset += static_cast<std::size_t>(count);
        }
    }
    Frame receive() {
        auto bytes = read(8);
        const auto size = u32(bytes,4);
        require(size >= 8 && size <= 65536,"tcp_frame_size_invalid");
        const auto payload = read(size-8);
        bytes.insert(bytes.end(),payload.begin(),payload.end());
        return decode_frame(bytes,{Channel::lobby_s2c,219,ClientVersion::legacy});
    }
    void await_close() {
        char byte{};
        const auto count = ::recv(socket,&byte,1,0);
        require(count == 0 || (count == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET),"peer_not_closed");
    }
    void save_and_close(Bytes setting) {
        send({105,std::move(setting)});
        require(::shutdown(socket,SD_SEND) == 0,"tcp_shutdown_failed");
        await_close();
    }
    void login(const Json& account) {
        send({759,id_bytes(113)},std::nullopt);
        Bytes payload;
        append_le(payload,0x12345678,4); append_le(payload,132,4); append_le(payload,0,4);
        payload.resize(144,0xca);
        const auto name = client_text(account.at("username").get<std::string>(),ClientProfile::original);
        const auto password = client_text("\xe5\xaf\x86\xe7\xa0\x81",ClientProfile::original);
        std::copy(name.begin(),name.end(),payload.begin()+12); payload[12+name.size()] = 0;
        std::copy(password.begin(),password.end(),payload.begin()+76); payload[76+password.size()] = 0;
        send({58,payload});
        const auto catalog = receive();
        require(catalog.wire_type == 67 && catalog.payload.size() == 212 && u32(catalog.payload,0) == 1 &&
                u32(catalog.payload,4) == account.at("role_id").get<std::uint32_t>(),"tcp_catalog_identity_wrong");
        const auto identity = receive();
        require(identity.wire_type == 1 && u32(identity.payload,0) == account.at("role_id").get<std::uint32_t>(),
                "tcp_login_identity_wrong");
    }
    void select(const Json& account,const Bytes& preferences) {
        const auto id = account.at("role_id").get<std::uint32_t>();
        send({34,id_bytes(id)});
        for (const auto type : {3U,9U,7U,140U,4U,2U,100U,103U,106U,30U}) {
            const auto frame = receive();
            require(frame.wire_type == type,"tcp_bootstrap_order_wrong");
            if (type == 3) require(frame.payload.size() == 220,"tcp_original_room_size_wrong");
            if (type == 7) {
                require(frame.payload.size() == 268 && u32(frame.payload,0) == id,"tcp_profile_identity_wrong");
                for (const auto& [offset,field] : std::initializer_list<std::pair<std::size_t,const char*>>{{76,"coins"},{84,"gold"},{92,"bank"}}) {
                    const auto expected = amount_bytes(account.at(field).get<double>());
                    require(std::equal(expected.begin(),expected.end(),frame.payload.begin()+static_cast<std::ptrdiff_t>(offset)),"tcp_profile_balance_stale");
                }
            }
            if (type == 106) require(frame.payload == preferences,"tcp_preferences_wrong");
        }
    }
};
struct RunningService {
    RichLobbyService& service;
    std::exception_ptr error;
    std::thread thread;
    explicit RunningService(RichLobbyService& target) : service(target),thread([this] {
        try { service.run(); } catch (...) { error = std::current_exception(); }
    }) {}
    void join() { service.stop(); if (thread.joinable()) thread.join(); }
    ~RunningService() { join(); }
};
Json bank_roundtrip(Client& client,Storage& storage,const Json& account) {
    for (int i=0;i<2;++i) {
        client.send({61,amount_bytes(250)});
        const auto reply = client.receive();
        require(reply.wire_type == 101 && reply.payload == amount_bytes(250),"tcp_deposit_delta_wrong");
    }
    for (const auto& [type,amount,code] : std::initializer_list<std::tuple<std::uint32_t,double,std::int32_t>>{
        {61,50,-131},{61,std::numeric_limits<double>::quiet_NaN(),-131},{61,500,-123},
        {62,601,-124},{62,-100,-131},{61,2147483648.0,-131}}) {
        client.send({type,amount_bytes(amount)});
        const auto reply = client.receive();
        require(reply.wire_type == 0xffffffffU && reply.payload.size() == 136 && u32(reply.payload,0) == type &&
            u32(reply.payload,4) == static_cast<std::uint32_t>(code),"tcp_bank_error_wrong");
        require(std::all_of(reply.payload.begin()+8,reply.payload.end(),[](auto byte) { return byte == 0; }),"tcp_bank_context_not_empty");
    }
    client.send({62,amount_bytes(100)});
    const auto reply = client.receive();
    require(reply.wire_type == 102 && reply.payload == amount_bytes(100),"tcp_withdraw_delta_wrong");
    const auto saved = storage.roles_for_username(account.at("username").get<std::string>()).at(0);
    require(saved.at("gold") == 2600 && saved.at("bank") == 500,"tcp_bank_transaction_wrong");
    return saved;
}
void concurrent_accounts_keep_independent_original_sessions() {
    const Winsock network;
    const Scratch scratch;
    Storage storage(scratch.path/L"original.sqlite3",ClientProfile::original);
    auto first = storage.dispatch("accounts.create",{{"username","\xe5\x8e\x9f\xe7\x89\x88\xe7\x94\xb2"},{"password","\xe5\xaf\x86\xe7\xa0\x81"}}).at("account");
    first = storage.dispatch("accounts.update",{{"role_id",first.at("role_id")},
        {"expected",{{"gold",first.at("gold")},{"bank",first.at("bank")},{"coins",first.at("coins")}}},
        {"changes",{{"gold",3000},{"bank",100},{"coins",12.5}}},{"reason","bank and exchange TCP test fixture"}}).at("account");
    const auto second = storage.dispatch("accounts.create",{{"username","\xe5\x8e\x9f\xe7\x89\x88\xe4\xb9\x99"},{"password","\xe5\xaf\x86\xe7\xa0\x81"}}).at("account");
    std::mutex mutex;
    std::condition_variable changed;
    bool listening = false;
    bool ownership_rejected = false;
    bool factory_rejected = false;
    bool bank_rejected = false;
    std::atomic_int factories{0};
    std::atomic_bool reject_next{false};
    RichLobbyService service({"127.0.0.1",0,local_lobby_handshake(),ClientVersion::legacy},LobbyCallbackFactory([&] {
        ++factories;
        if (reject_next.exchange(false)) throw CodecError("test_callback_factory_rejected");
        return make_original_lobby_callbacks(storage,policy());
    }),[&](const std::string& line) {
        const std::lock_guard lock(mutex);
        if (line.starts_with("lobby_listening ")) listening = true;
        if (line.find("reason=original_lobby_role_not_owned") != std::string::npos) ownership_rejected = true;
        if (line.find("reason=test_callback_factory_rejected") != std::string::npos) factory_rejected = true;
        if (line.starts_with("connection_id=") && line.ends_with(" lobby_request_rejected request_type=61 error_code=-131")) bank_rejected = true;
        changed.notify_all();
    });
    RunningService running(service);
    {
        std::unique_lock lock(mutex);
        require(changed.wait_for(lock,std::chrono::seconds(5),[&] { return listening; }),"tcp_listener_not_started");
    }
    require(factories == 0,"callback_factory_called_during_preflight");
    Client a(service.bound_port()),b(service.bound_port());
    a.login(first); b.login(second);
    a.select(first,{'4','1','1','0',0}); b.select(second,{'4','1','1','0',0});
    first = bank_roundtrip(a,storage,first);
    first = original_exchange_test::roundtrip(a,storage,first);
    const auto untouched = storage.roles_for_username(second.at("username").get<std::string>()).at(0);
    require(untouched.at("gold") == second.at("gold") && untouched.at("bank") == second.at("bank"),"tcp_bank_other_account_changed");
    a.save_and_close({'0','0','0','1','6',0});
    Client intruder(service.bound_port());
    intruder.login(first);
    intruder.send({34,id_bytes(second.at("role_id").get<std::uint32_t>())});
    intruder.await_close();
    reject_next.store(true);
    Client rejected(service.bound_port(),false);
    rejected.await_close();
    b.save_and_close({'0','0','0','3','2',0});
    Client restored_a(service.bound_port()),restored_b(service.bound_port());
    restored_a.login(first); restored_b.login(second);
    restored_b.select(second,{'4','6',0}); restored_a.select(first,{'3','0',0});
    require(storage.preferences_for_username(first.at("username").get<std::string>()) == "00016" &&
            storage.preferences_for_username(second.at("username").get<std::string>()) == "00032","saved_preference_text_or_ownership_wrong");
    running.join();
    if (running.error) std::rethrow_exception(running.error);
    require(ownership_rejected,"cross_account_rejection_reason_missing");
    require(factory_rejected,"factory_rejection_reason_missing");
    require(bank_rejected,"bank_rejection_code_missing_from_logs");
    require(factories == 6,"callback_factory_not_once_per_connection");
    require(service.bound_port() == 0 && service.authenticated_sessions() == 0,"tcp_shutdown_state_wrong");
}
#endif
}
int main() {
    try {
#ifdef _WIN32
        concurrent_accounts_keep_independent_original_sessions();
        std::cout << "original lobby TCP isolation tests PASS\n";
        return 0;
#else
        std::cerr << "original lobby TCP isolation tests require Windows\n";
        return 77;
#endif
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
