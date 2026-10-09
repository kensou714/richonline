#include "service.hpp"
#include "pending_game_admissions.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <condition_variable>
#include <atomic>
#include <iostream>
#include <mutex>
#include <thread>

namespace {
using namespace richnet;
void require(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
struct Network {
    Network() { WSADATA value{}; require(WSAStartup(MAKEWORD(2,2), &value) == 0, "test_winsock_failed"); }
    ~Network() { WSACleanup(); }
};
struct Client {
    SOCKET socket = INVALID_SOCKET;
    explicit Client(std::uint16_t port) {
        socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        require(socket != INVALID_SOCKET, "test_socket_failed");
        const DWORD timeout = 2000;
        require(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0,
                "test_receive_timeout_failed");
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        require(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1, "test_address_failed");
        require(connect(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0, "test_connect_failed");
    }
    ~Client() { if (socket != INVALID_SOCKET) closesocket(socket); }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    void send(View bytes) const {
        while (!bytes.empty()) {
            const auto count = ::send(socket, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), 0);
            require(count > 0, "test_send_failed");
            bytes = bytes.subspan(static_cast<std::size_t>(count));
        }
    }
    Bytes read(std::size_t size) const {
        Bytes result(size);
        std::size_t offset = 0;
        while (offset < size) {
            const auto count = recv(socket, reinterpret_cast<char*>(result.data()+offset), static_cast<int>(size-offset), 0);
            require(count > 0, "test_reply_missing_or_peer_blocked");
            offset += static_cast<std::size_t>(count);
        }
        return result;
    }
    void closed() const {
        char byte{};
        const auto count = recv(socket, &byte, 1, 0);
        require(count == 0 || (count == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET), "test_peer_not_closed");
    }
    void reset() {
        const linger abortive{1,0};
        require(setsockopt(socket,SOL_SOCKET,SO_LINGER,reinterpret_cast<const char*>(&abortive),sizeof(abortive))==0,
            "test_reset_linger_failed");
        closesocket(socket); socket=INVALID_SOCKET;
    }
};
struct Running {
    GameService& service;
    std::exception_ptr error;
    std::thread thread;
    explicit Running(GameService& instance) : service(instance), thread([this] {
        try { service.run(); } catch (...) { error = std::current_exception(); }
    }) {}
    ~Running() { service.stop(); if (thread.joinable()) thread.join(); }
};
GameAdmission descriptor(ClientVersion version, std::uint32_t self) {
    GameAdmission result{0,13,self,{1,0x33,0,0x7f,0x84,0xab,0x19,0xfe},0x3175339aU,{}};
    if (version == ClientVersion::legacy) result.legacy_fields = std::array<std::uint32_t,2>{0x11889933U,0x99443311U};
    return result;
}
Bytes admission(ClientVersion version, std::uint32_t self) {
    return encode_frame(encode_game_admission(descriptor(version,self), version), {Channel::game_c2s,{},version});
}
Bytes message(ClientVersion version) {
    Envelope299 envelope{0,1,{0x97,0x6b,0x98,0x6c,0x99,0x6b,0x9a,0x6d},{}};
    if (version == ClientVersion::legacy) envelope.tail = {0x12,0x98,0x44,0xaa};
    return encode_frame(encode_envelope(envelope,version), {Channel::game_c2s,{},version});
}
void real_tcp_admission_and_concurrent_peer(ClientVersion version) {
    PendingGameAdmissions pending;
    const auto now = AdmissionClock::now();
    pending.prepare({10,version,descriptor(version,25),now+std::chrono::minutes(1)},now);
    pending.prepare({11,version,descriptor(version,26),now+std::chrono::minutes(1)},now);
    int accepted = 0, dispatched = 0, released = 0;
    const GameCallbackFactory factory = [&] {
        GameCallbacks callbacks;
        callbacks.authorize_admission = [&](const GameAdmission& value) {
            return pending.consume(version,value,AdmissionClock::now()).has_value();
        };
        callbacks.admitted = [&](const GameAdmission&) { ++accepted; return std::vector<Frame>{{55,{0x43}}}; };
        callbacks.message = [&](const GameAdmission&, const Envelope299&, View plain) {
            const Bytes expected{1,0};
            require(std::equal(plain.begin(),plain.end(),expected.begin(),expected.end()), "test_message_not_decoded");
            ++dispatched;
            return std::vector<Frame>{{56,{0x44}}};
        };
        callbacks.disconnected = [&](const GameAdmission&) { ++released; };
        return callbacks;
    };
    std::mutex mutex;
    std::condition_variable ready;
    bool listening = false;
    GameService service({"127.0.0.1",0,version}, factory, [&](const std::string&) {
        if (service.bound_port() != 0) {
            const std::lock_guard lock(mutex);
            listening = true;
            ready.notify_one();
        }
    });
    Running running(service);
    {
        std::unique_lock lock(mutex);
        require(ready.wait_for(lock,std::chrono::seconds(5),[&] { return listening; }), "test_listener_not_ready");
    }
    const Client first(service.bound_port());
    const auto enter = admission(version,25);
    auto input = enter;
    const auto request = message(version);
    input.insert(input.end(),request.begin(),request.end());
    first.send(input);
    const Bytes expected{55,0,0,0,9,0,0,0,0x43,56,0,0,0,9,0,0,0,0x44};
    require(first.read(expected.size()) == expected, "test_tcp_reply_bytes_wrong");
    const Client replay(service.bound_port());
    replay.send(enter);
    replay.closed();
    const Client stalled(service.bound_port());
    stalled.send(View(enter).first(1));
    const Client second(service.bound_port());
    const auto second_admission = admission(version,26);
    for (const auto byte : second_admission) second.send(View(&byte,1));
    second.send(request);
    require(second.read(expected.size()) == expected, "test_stalled_peer_blocks_other_player");
    const auto stop_started = AdmissionClock::now();
    service.stop();
    running.thread.join();
    if (running.error) std::rethrow_exception(running.error);
    require(AdmissionClock::now()-stop_started < std::chrono::seconds(2), "test_game_stop_blocked_on_idle_peer");
    require(service.bound_port() == 0 && accepted == 2 && dispatched == 2 && released == 2, "test_game_lifecycle_counts_wrong");
    first.closed(); second.closed(); stalled.closed();
}
void real_tcp_notifies_feed_and_poll_after_send() {
    std::mutex mutex; std::condition_variable changed;
    bool listening=false; std::vector<std::uint32_t> confirmed;
    std::atomic_bool requested{false},polled{false};
    const GameCallbackFactory factory=[&] {
        GameCallbacks callbacks;
        callbacks.authorize_admission=[](const GameAdmission& value){return value==descriptor(ClientVersion::richonline,25);};
        callbacks.admitted=[](const GameAdmission&){return std::vector<Frame>{{55,{0x43}}};};
        callbacks.message=[&](const GameAdmission&,const Envelope299&,View){requested=true;return std::vector<Frame>{{56,{0x44}}};};
        callbacks.poll=[&](const GameAdmission&) {
            if(!requested || polled.exchange(true)) return std::vector<Frame>{};
            return std::vector<Frame>{{57,{0x45}}};
        };
        callbacks.sent=[&](const GameAdmission& value,const Frame& frame) {
            require(value==descriptor(ClientVersion::richonline,25),"tcp_sent_identity_changed");
            const std::lock_guard lock(mutex); confirmed.push_back(frame.wire_type); changed.notify_all();
        };
        return callbacks;
    };
    GameService service({"127.0.0.1",0,ClientVersion::richonline},factory,[&](const std::string&) {
        if(service.bound_port()!=0) { const std::lock_guard lock(mutex); listening=true;changed.notify_all(); }
    });
    Running running(service);
    { std::unique_lock lock(mutex); require(changed.wait_for(lock,std::chrono::seconds(5),[&]{return listening;}),"sent_listener_not_ready"); }
    Client client(service.bound_port()); client.send(admission(ClientVersion::richonline,25));
    require(client.read(9)==Bytes({55,0,0,0,9,0,0,0,0x43}),"sent_admission_reply_wrong");
    client.send(message(ClientVersion::richonline));
    require(client.read(18)==Bytes({56,0,0,0,9,0,0,0,0x44,57,0,0,0,9,0,0,0,0x45}),"sent_feed_poll_replies_wrong");
    { std::unique_lock lock(mutex); require(changed.wait_for(lock,std::chrono::seconds(5),[&]{return confirmed.size()==3;}),"sent_callbacks_missing");
      require(confirmed==std::vector<std::uint32_t>({55,56,57}),"sent_feed_poll_callback_order_wrong"); }
    service.stop(); running.thread.join(); if(running.error)std::rethrow_exception(running.error);
}
void real_tcp_failed_whole_send_never_checkpoints() {
    std::mutex mutex; std::condition_variable changed;
    bool listening=false,preparing=false,reset=false,disconnected=false,send_failed=false;
    unsigned terminal_checkpoints=0;
    const GameCallbackFactory factory=[&] {
        GameCallbacks callbacks;
        callbacks.authorize_admission=[](const GameAdmission& value){return value==descriptor(ClientVersion::richonline,25);};
        callbacks.admitted=[](const GameAdmission&){return std::vector<Frame>{{55,{0x43}}};};
        callbacks.message=[&](const GameAdmission&,const Envelope299&,View) {
            std::unique_lock lock(mutex); preparing=true; changed.notify_all();
            require(changed.wait_for(lock,std::chrono::seconds(5),[&]{return reset;}),"tcp_reset_fixture_timeout");
            // An abortive close occurs before encoding/sending this maximum-size legal frame.
            return std::vector<Frame>{{56,Bytes(max_frame_total-8,0x44)},{57,{0x45}}};
        };
        callbacks.sent=[&](const GameAdmission&,const Frame& frame) {
            if(frame.wire_type==56 || frame.wire_type==57) { const std::lock_guard lock(mutex);++terminal_checkpoints; }
        };
        callbacks.disconnected=[&](const GameAdmission&) { const std::lock_guard lock(mutex);disconnected=true;changed.notify_all(); };
        return callbacks;
    };
    GameService service({"127.0.0.1",0,ClientVersion::richonline},factory,[&](const std::string& line) {
        const std::lock_guard lock(mutex);
        if(service.bound_port()!=0)listening=true;
        if(line.find("game_connection_closed reason=game_send_failed")!=std::string::npos)send_failed=true;
        changed.notify_all();
    });
    Running running(service);
    { std::unique_lock lock(mutex); require(changed.wait_for(lock,std::chrono::seconds(5),[&]{return listening;}),"failed_send_listener_not_ready"); }
    Client client(service.bound_port()); client.send(admission(ClientVersion::richonline,25)); client.read(9);
    client.send(message(ClientVersion::richonline));
    { std::unique_lock lock(mutex); require(changed.wait_for(lock,std::chrono::seconds(5),[&]{return preparing;}),"failed_send_action_not_entered"); }
    client.reset();
    { const std::lock_guard lock(mutex);reset=true;changed.notify_all(); }
    { std::unique_lock lock(mutex); require(changed.wait_for(lock,std::chrono::seconds(5),[&]{return disconnected && send_failed;}),"whole_send_failure_not_observed");
      require(terminal_checkpoints==0,"failed_send_advanced_terminal_checkpoint"); }
    service.stop(); running.thread.join(); if(running.error)std::rethrow_exception(running.error);
}
}
int main() {
    try {
        const Network network;
        real_tcp_admission_and_concurrent_peer(ClientVersion::richonline);
        real_tcp_admission_and_concurrent_peer(ClientVersion::legacy);
        real_tcp_notifies_feed_and_poll_after_send();
        real_tcp_failed_whole_send_never_checkpoints();
        std::cout << "game transport real TCP tests PASS\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
