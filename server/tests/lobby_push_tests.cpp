#include "lobby.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <map>
#include <mutex>
#include <thread>
#include <type_traits>
#include <utility>

namespace {
using namespace richnet;
void require(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
template<class Action> void rejects(Action action) {
    try { action(); } catch (const CodecError&) { return; }
    throw std::runtime_error("expected_codec_error");
}
LobbyOptions options() { return {"127.0.0.1",0,local_lobby_handshake(),ClientVersion::legacy}; }
Bytes packet(const Frame& frame, std::optional<std::int32_t> key = 219) {
    return encode_frame(frame,{Channel::lobby_c2s,key,ClientVersion::legacy});
}
Bytes public_packet() { return packet({759,{113,0,0,0}},std::nullopt); }
Bytes login_packet() {
    Bytes payload(144,0); payload[4] = 132; payload[12] = 'a'; payload[76] = 'p';
    return packet({58,payload});
}
LobbyCallbacks callbacks() {
    LobbyCallbacks value;
    value.verify_credentials = [](const std::string&, View) { return true; };
    value.login_responses = [](const LobbyLogin&) { return std::vector<Frame>{{1,{1,2,3,4}}}; };
    value.authenticated_request = [](const LobbyLogin&, const Frame&) { return std::vector<Frame>{{9,{5,6}}}; };
    return value;
}
void authenticate(RichLobbySession& session) {
    static_cast<void>(session.start()); static_cast<void>(session.feed(public_packet()));
    static_cast<void>(session.feed(login_packet()));
}
std::uint32_t type(const Bytes& value) {
    return decode_frame(value,{Channel::lobby_s2c,219,ClientVersion::legacy}).wire_type;
}
void fragmented_requests_preserve_notification_order() {
    std::vector<Frame> queued{{17,{1,2,3,4}}}; int drains = 0, closed = 0;
    auto provider = callbacks();
    provider.drain_outbound = [&] { ++drains; return std::exchange(queued,{}); };
    provider.disconnected = [&] { ++closed; };
    provider.authenticated_request = [&](const LobbyLogin&, const Frame&) {
        queued.push_back({18,{4,3,2,1}}); return std::vector<Frame>{{9,{7,8}}};
    };
    {
        RichLobbySession session(options(),provider);
        require(session.drain_outbound().empty() && drains == 0,"unauthenticated_drain");
        static_cast<void>(session.start());
        for (const auto byte : public_packet()) require(session.feed(View(&byte,1)).empty(),"partial_handshake_response");
        require(session.drain_outbound().empty() && drains == 0,"prelogin_drain");
        const auto logged_in = session.feed(login_packet());
        require(logged_in.size() == 2 && type(logged_in[0]) == 1 && type(logged_in[1]) == 17,"login_order");
        queued.push_back({17,{9,8,7,6}});
        const auto request = packet({34,{1,0,0,0}});
        require(session.feed(View(request).first(7)).empty(),"partial_request_processed");
        const auto output = session.feed(View(request).subspan(7));
        require(output.size() == 3 && type(output[0]) == 17 && type(output[1]) == 9 && type(output[2]) == 18,"push_order");
        auto combined = request; combined.insert(combined.end(),request.begin(),request.end());
        const auto coalesced = session.feed(combined);
        require(coalesced.size() == 4 && type(coalesced[0]) == 9 && type(coalesced[1]) == 18 &&
                type(coalesced[2]) == 9 && type(coalesced[3]) == 18,"coalesced_push_order");
        session.finish(); session.finish();
        require(session.drain_outbound().empty() && closed == 1,"repeated_cleanup");
    }
    require(closed == 1,"destructor_double_cleanup");
}
void failures_cleanup_once_and_destructors_do_not_throw() {
    for (int scenario = 0; scenario < 7; ++scenario) {
        int closed = 0; auto provider = callbacks();
        provider.disconnected = [&] { ++closed; throw CodecError("cleanup_fixture"); };
        if (scenario == 5) provider.authenticated_request = [](const LobbyLogin&, const Frame&) -> std::vector<Frame> {
            throw CodecError("request_fixture");
        };
        if (scenario == 6) provider.authenticated_request = [](const LobbyLogin&, const Frame&) {
            return std::vector<Frame>{{579,{1,2,3,4}}};
        };
        {
            RichLobbySession session(scenario == 4 ? LobbyOptions{} : options(),provider,[](const std::string& line) {
                if (line == "lobby_disconnect_callback_failed") throw CodecError("logger_fixture");
            });
            if (scenario == 1) {
                static_cast<void>(session.start()); auto bad = public_packet(); bad[0] = 0;
                rejects([&] { static_cast<void>(session.feed(bad)); });
            } else if (scenario == 2) {
                static_cast<void>(session.start()); static_cast<void>(session.feed(View(public_packet()).first(7)));
                rejects([&] { session.finish(); });
            } else if (scenario == 4) {
                rejects([&] { static_cast<void>(session.start()); });
            } else if (scenario != 0) {
                authenticate(session);
                if (scenario == 3) rejects([&] { static_cast<void>(session.feed(login_packet())); });
                else rejects([&] { static_cast<void>(session.feed(packet({34,{1,0,0,0}}))); });
            }
            if (scenario != 0) require(closed == 1 && session.state() == LobbyState::closed,"failure_cleanup_missing");
        }
        require(closed == 1,"failure_cleanup_repeated");
    }
    for (const bool reject_login : {false,true}) {
        int closed = 0; auto provider = callbacks();
        provider.disconnected = [&] { ++closed; };
        provider.verify_credentials = [=](const std::string&, View) { return !reject_login; };
        provider.drain_outbound = []() -> std::vector<Frame> { throw CodecError("queue_fixture"); };
        RichLobbySession session(options(),provider); static_cast<void>(session.start());
        static_cast<void>(session.feed(public_packet()));
        rejects([&] { static_cast<void>(session.feed(login_packet())); });
        require(closed == 1,"auth_or_drain_cleanup_missing");
    }
}
struct Client {
    SOCKET socket = ::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    explicit Client(std::uint16_t port) {
        require(socket != INVALID_SOCKET,"socket_create");
        const DWORD timeout = 5000;
        require(setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout)) == 0,"timeout");
        sockaddr_in target{}; target.sin_family = AF_INET; target.sin_port = htons(port);
        require(inet_pton(AF_INET,"127.0.0.1",&target.sin_addr) == 1,"address");
        require(connect(socket,reinterpret_cast<sockaddr*>(&target),sizeof(target)) == 0,"connect");
        static_cast<void>(read(20));
    }
    ~Client() { if (socket != INVALID_SOCKET) closesocket(socket); }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    void send(View bytes) {
        while (!bytes.empty()) {
            const auto count = ::send(socket,reinterpret_cast<const char*>(bytes.data()),static_cast<int>(bytes.size()),0);
            require(count > 0,"send"); bytes = bytes.subspan(static_cast<std::size_t>(count));
        }
    }
    Bytes read(std::size_t size) {
        Bytes bytes(size);
        for (std::size_t offset = 0; offset < size;) {
            const auto count = recv(socket,reinterpret_cast<char*>(bytes.data()+offset),static_cast<int>(size-offset),0);
            require(count > 0,"receive"); offset += static_cast<std::size_t>(count);
        }
        return bytes;
    }
    Frame receive() {
        auto bytes = read(8); const auto size = read_le(View(bytes).subspan(4,4));
        require(size >= 8 && size <= max_frame_total,"response_size");
        const auto tail = read(size-8); bytes.insert(bytes.end(),tail.begin(),tail.end());
        return decode_frame(bytes,{Channel::lobby_s2c,219,ClientVersion::legacy});
    }
    void login() { send(public_packet()); send(login_packet()); require(receive().wire_type == 1,"login"); }
    void abort() {
        const linger reset{1,0};
        require(setsockopt(socket,SOL_SOCKET,SO_LINGER,reinterpret_cast<const char*>(&reset),sizeof(reset)) == 0,"linger");
        closesocket(std::exchange(socket,INVALID_SOCKET));
    }
};
struct Running {
    RichLobbyService& service; std::exception_ptr error; std::thread thread;
    explicit Running(RichLobbyService& value) : service(value),thread([this] {
        try { service.run(); } catch (...) { error = std::current_exception(); }
    }) {}
    ~Running() { join(); }
    void join() { service.stop(); if (thread.joinable()) thread.join(); }
};
void tcp_idle_broadcast_failures_and_stop_release_each_peer() {
    WSADATA network{}; require(WSAStartup(MAKEWORD(2,2),&network) == 0,"winsock");
    struct Cleanup { ~Cleanup() { WSACleanup(); } } cleanup;
    std::mutex mutex; std::condition_variable changed;
    bool listening = false, sending = false, release_send = false, send_failed = false;
    unsigned next_id = 0;
    std::map<unsigned,std::vector<Frame>> queues; std::map<unsigned,int> disconnected;
    RichLobbyService service(options(),LobbyCallbackFactory([&] {
        const std::lock_guard lock(mutex); const auto id = ++next_id; queues[id];
        auto provider = callbacks();
        provider.drain_outbound = [&,id] {
            const std::lock_guard guard(mutex); return std::exchange(queues.at(id),{});
        };
        provider.disconnected = [&,id] {
            const std::lock_guard guard(mutex); ++disconnected[id]; changed.notify_all();
        };
        provider.authenticated_request = [&](const LobbyLogin&,const Frame& frame) {
            std::unique_lock guard(mutex);
            if (frame.wire_type == 99) {
                sending = true; changed.notify_all();
                require(changed.wait_for(guard,std::chrono::seconds(5),[&] { return release_send; }),"send_barrier");
                return std::vector<Frame>(20,Frame{18,Bytes(65536,0x37)});
            }
            for (auto& [peer,queue] : queues) { static_cast<void>(peer); queue.push_back({18,{4,3,2,1}}); }
            return std::vector<Frame>{{9,{5,6}}};
        };
        return provider;
    }),[&](const std::string& line) {
        const std::lock_guard lock(mutex);
        if (line.starts_with("lobby_listening ")) listening = true;
        if (line.find("reason=lobby_send_failed") != std::string::npos) send_failed = true;
        changed.notify_all();
    });
    Running running(service);
    auto await = [&](auto predicate) {
        std::unique_lock lock(mutex); require(changed.wait_for(lock,std::chrono::seconds(5),predicate),"event_timeout");
    };
    await([&] { return listening; });
    Client a(service.bound_port()), b(service.bound_port()); a.login(); b.login();
    {
        const std::lock_guard lock(mutex);
        queues.at(1).push_back({17,{1,2,3,4}}); queues.at(2).push_back({17,{8,7,6,5}});
    }
    require(a.receive().payload == Bytes({1,2,3,4}) && b.receive().payload == Bytes({8,7,6,5}),"idle_push_or_isolation");
    a.send(packet({34,{1,0,0,0}}));
    require(a.receive().wire_type == 9 && a.receive().wire_type == 18 && b.receive().wire_type == 18,"tcp_broadcast_order");
    a.send(packet({99,{}})); await([&] { return sending; }); a.abort();
    { const std::lock_guard lock(mutex); release_send = true; changed.notify_all(); }
    await([&] { return disconnected[1] == 1; });
    b.send(packet({34,{2,0,0,0}}));
    require(b.receive().wire_type == 9 && b.receive().wire_type == 18,"peer_failure_stopped_service");
    Client eof(service.bound_port()); eof.login();
    require(shutdown(eof.socket,SD_SEND) == 0,"eof_shutdown"); await([&] { return disconnected[3] == 1; });
    Client fragmented(service.bound_port()); fragmented.send(View(public_packet()).first(7));
    require(shutdown(fragmented.socket,SD_SEND) == 0,"fragmented_shutdown"); await([&] { return disconnected[4] == 1; });
    running.join(); if (running.error) std::rethrow_exception(running.error);
    require(send_failed,"send_failure_not_exercised");
    require(disconnected.size() == 4 && std::all_of(disconnected.begin(),disconnected.end(),[](const auto& entry) { return entry.second == 1; }),"cleanup_count");
    require(service.authenticated_sessions() == 0 && service.bound_port() == 0,"stop_state");
}
}
static_assert(!std::is_copy_constructible_v<richnet::RichLobbySession>);
static_assert(!std::is_move_constructible_v<richnet::RichLobbySession>);
int main() {
    try {
        fragmented_requests_preserve_notification_order();
        failures_cleanup_once_and_destructors_do_not_throw();
        tcp_idle_broadcast_failures_and_stop_release_each_peer();
        std::cout << "lobby push and lifecycle tests PASS\n"; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
