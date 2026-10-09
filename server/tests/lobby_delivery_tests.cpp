#include "lobby.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

namespace {
using namespace richnet;
void require(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
struct Hub {
    std::mutex mutex;
    std::condition_variable changed;
    bool listening = false;
    std::map<std::string, std::vector<Frame>> queues;
    std::map<std::string, int> departures;
    std::map<std::string,std::vector<Frame>> delivered;
    LobbyCallbacks connect() {
        auto name = std::make_shared<std::string>();
        return {
            [](const std::string&, View) { return true; },
            [this, name](const LobbyLogin& login) {
                const std::lock_guard lock(mutex);
                *name = login.username_utf8;
                queues[*name];
                return std::vector<Frame>{{1, {1, 2, 3, 4}}};
            },
            [this](const LobbyLogin& login, const Frame& frame) {
                const std::lock_guard lock(mutex);
                for (auto& [name, queue] : queues)
                    if (name != login.username_utf8) queue.push_back({15, frame.payload});
                return std::vector<Frame>{};
            },
            [this, name] {
                const std::lock_guard lock(mutex);
                return std::exchange(queues[*name], {});
            },
            [this, name] {
                const std::lock_guard lock(mutex);
                if (name->empty()) return;
                ++departures[*name];
                queues.erase(*name);
                changed.notify_all();
            },
            [this,name](const Frame& frame) {
                const std::lock_guard lock(mutex);
                if(name->empty()) return;
                delivered[*name].push_back(frame);changed.notify_all();
            }
        };
    }
};
struct Client {
    SOCKET socket = INVALID_SOCKET;
    std::int32_t key;
    Client(std::uint16_t port, std::int32_t client_exponent, const std::string& username) : key(modpow_signed32(64, client_exponent, 251)) {
        socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        require(socket != INVALID_SOCKET, "socket_failed");
        const DWORD timeout = 3000;
        require(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0, "timeout_failed");
        sockaddr_in address{};
        address.sin_family = AF_INET; address.sin_port = htons(port);
        require(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1, "address_failed");
        require(::connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "connect_failed");
        static_cast<void>(read(20));
        Bytes public_value;
        append_le(public_value, static_cast<std::uint32_t>(modpow_signed32(5, client_exponent, 251)), 4);
        send(encode_frame({759, public_value}, {Channel::lobby_c2s, std::nullopt, ClientVersion::richonline}));
        Bytes payload(144, 0);
        std::copy(username.begin(), username.end(), payload.begin() + 12);
        payload[76] = 'p';
        send(encode_frame({58, payload}, {Channel::lobby_c2s, key, ClientVersion::richonline}));
        require(frame().wire_type == 1, "login_failed");
    }
    ~Client() { close(); }
    void close() { if (socket != INVALID_SOCKET) { closesocket(socket); socket = INVALID_SOCKET; } }
    void send(View bytes) {
        while (!bytes.empty()) {
            const auto n = ::send(socket, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), 0);
            require(n > 0, "send_failed"); bytes = bytes.subspan(static_cast<std::size_t>(n));
        }
    }
    Bytes read(std::size_t count) {
        Bytes output(count); std::size_t position = 0;
        while (position < count) {
            const auto n = recv(socket, reinterpret_cast<char*>(output.data() + position), static_cast<int>(count - position), 0);
            require(n > 0, "read_failed"); position += static_cast<std::size_t>(n);
        }
        return output;
    }
    Frame frame() {
        auto packet = read(8);
        const auto total = read_le(View(packet).subspan(4));
        require(total >= 8 && total <= max_frame_total, "bad_total");
        auto body = read(total - 8); packet.insert(packet.end(), body.begin(), body.end());
        return decode_frame(packet, {Channel::lobby_s2c, key, ClientVersion::richonline});
    }
};
void unit_cleanup_and_pre_auth_poll() {
    int drains = 0, disconnects = 0, delivered=0;
    auto callbacks = LobbyCallbacks{};
    callbacks.verify_credentials = [](const std::string&, View) { return true; };
    callbacks.login_responses = [](const LobbyLogin&) { return std::vector<Frame>{{1, {1}}}; };
    callbacks.drain_outbound = [&] { ++drains; return std::vector<Frame>{{15, {9}}}; };
    callbacks.disconnected = [&] { ++disconnects; };
    callbacks.sent=[&](const Frame& frame) {require(frame.wire_type==15&&frame.payload==Bytes{9},"send_observer_wrong_plain_frame");++delivered;};
    RichLobbySession session({"127.0.0.1", 0, local_lobby_handshake()}, callbacks);
    require(session.poll().empty() && drains == 0, "preauth_drained");
    static_cast<void>(session.start());
    require(session.poll().empty() && drains == 0, "handshake_drained");
    static_cast<void>(session.feed(encode_frame({759, {113, 0, 0, 0}}, {Channel::lobby_c2s, std::nullopt, ClientVersion::richonline})));
    Bytes payload(144, 0); payload[12] = 'u'; payload[76] = 'p';
    static_cast<void>(session.feed(encode_frame({58, payload}, {Channel::lobby_c2s, 219, ClientVersion::richonline})));
    const auto before_poll = drains;
    const auto packets = session.poll();
    require(drains == before_poll + 1 && decode_frame(packets.at(0), {Channel::lobby_s2c, 219, ClientVersion::richonline}).payload == Bytes{9}, "poll_not_encrypted");
    require(delivered==0,"encode_or_enqueue_marked_delivered");
    session.sent(packets.front());require(delivered==1,"successful_whole_frame_not_observed");
    auto truncated_packet=packets.front();truncated_packet.pop_back();bool refused=false;
    try{session.sent(truncated_packet);}catch(const CodecError&){refused=true;}
    require(refused&&delivered==1,"partial_frame_marked_delivered");
    static_cast<void>(session.feed(Bytes{0}));
    bool truncated = false;
    try { session.finish(); } catch (const CodecError&) { truncated = true; }
    session.finish();
    require(truncated && disconnects == 1 && session.poll().empty(), "cleanup_not_idempotent");
    auto rejected_callbacks = callbacks;
    rejected_callbacks.login_responses = [](const LobbyLogin&) -> std::vector<Frame> { throw CodecError("provider_failed"); };
    RichLobbySession rejected({"127.0.0.1", 0, local_lobby_handshake()}, rejected_callbacks);
    static_cast<void>(rejected.start());
    static_cast<void>(rejected.feed(encode_frame({759, {113, 0, 0, 0}}, {Channel::lobby_c2s, std::nullopt, ClientVersion::richonline})));
    bool failed = false;
    try { static_cast<void>(rejected.feed(encode_frame({58, payload}, {Channel::lobby_c2s, 219, ClientVersion::richonline}))); }
    catch (const CodecError&) { failed = true; }
    rejected.finish();
    require(failed && disconnects == 2, "authenticated_provider_failure_not_cleaned");
}
void tcp_idle_delivery_and_disconnect_cleanup() {
    Hub hub;
    RichLobbyService service({"127.0.0.1", 0, local_lobby_handshake()}, [&] { return hub.connect(); }, [&](const std::string& line) {
        if (line.starts_with("lobby_listening")) { const std::lock_guard lock(hub.mutex); hub.listening = true; hub.changed.notify_all(); }
    });
    std::exception_ptr failure;
    std::thread worker([&] { try { service.run(); } catch (...) { failure = std::current_exception(); } });
    try {
        { std::unique_lock lock(hub.mutex); require(hub.changed.wait_for(lock, std::chrono::seconds(3), [&] { return hub.listening; }), "not_listening"); }
        Client first(service.bound_port(), 3, "first"), second(service.bound_port(), 5, "second");
        first.send(encode_frame({15, {0x11, 0x42, 0x93, 0xe4}}, {Channel::lobby_c2s, first.key, ClientVersion::richonline}));
        const auto broadcast = second.frame();
        require(first.key != second.key && broadcast.wire_type == 15 && broadcast.payload == Bytes({0x11, 0x42, 0x93, 0xe4}), "idle_broadcast_wrong_key_or_payload");
        {std::unique_lock lock(hub.mutex);require(hub.changed.wait_for(lock,std::chrono::seconds(3),[&]{
            const auto& delivered=hub.delivered["second"];return std::any_of(delivered.begin(),delivered.end(),[](const Frame& frame){return frame.wire_type==15&&frame.payload==Bytes({0x11,0x42,0x93,0xe4});});
        }),"real_tcp_whole_send_not_observed");hub.queues["second"].push_back({58,{0x78,0x56,0,0}});}
        const auto finished=second.frame();require(finished.wire_type==58&&finished.payload==Bytes({0x78,0x56,0,0}),"real_tcp_finish_notification");
        {std::unique_lock lock(hub.mutex);require(hub.changed.wait_for(lock,std::chrono::seconds(3),[&]{
            const auto& delivered=hub.delivered["second"];return std::any_of(delivered.begin(),delivered.end(),[](const Frame& frame){return frame.wire_type==58&&frame.payload==Bytes({0x78,0x56,0,0});});
        }),"real_tcp_finish_not_observed");}
        first.close();
        { std::unique_lock lock(hub.mutex); require(hub.changed.wait_for(lock, std::chrono::seconds(3), [&] { return hub.departures["first"] == 1; }), "closed_client_not_cleaned"); }
        Client malformed(service.bound_port(), 7, "malformed");
        Bytes bad_magic(12, 0);
        malformed.send(bad_magic);
        { std::unique_lock lock(hub.mutex); require(hub.changed.wait_for(lock, std::chrono::seconds(3), [&] { return hub.departures["malformed"] == 1; }), "parse_error_not_cleaned"); }
        service.stop(); worker.join();
        if (failure) std::rethrow_exception(failure);
        require(hub.departures["first"] == 1 && hub.departures["second"] == 1 && hub.departures["malformed"] == 1 && service.authenticated_sessions() == 0, "stop_not_cleaned");
    } catch (...) { service.stop(); if (worker.joinable()) worker.join(); throw; }
}
void explicit_logout_has_strict_state_and_payload_boundaries() {
    for (const auto version : {ClientVersion::richonline,ClientVersion::legacy}) {
        int cleaned=0, dispatched=0;
        LobbyCallbacks callbacks;
        callbacks.verify_credentials=[](const std::string&,View) { return true; };
        callbacks.login_responses=[](const LobbyLogin&) { return std::vector<Frame>{{1,{1}}}; };
        callbacks.authenticated_request=[&](const LobbyLogin&,const Frame&) -> std::vector<Frame> {
            ++dispatched; throw CodecError("fixture_unsupported_request");
        };
        callbacks.disconnected=[&] { ++cleaned; };
        for (const auto payload : {Bytes{},Bytes{1}}) {
            RichLobbySession session({"127.0.0.1",0,local_lobby_handshake(),version},callbacks);
            static_cast<void>(session.start());
            static_cast<void>(session.feed(encode_frame({759,{113,0,0,0}},{Channel::lobby_c2s,std::nullopt,version})));
            Bytes login(144,0); login[12]='u'; login[76]='p';
            if (version==ClientVersion::legacy) login[4]=132;
            static_cast<void>(session.feed(encode_frame({58,login},{Channel::lobby_c2s,219,version})));
            bool rejected=false;
            try {
                require(session.feed(encode_frame({0xffffffffU,payload},{Channel::lobby_c2s,219,version})).empty(),"logout_has_fake_ack");
            } catch (const CodecError& error) {
                rejected=true;
                require(std::string(error.what())==(version==ClientVersion::legacy ? "fixture_unsupported_request" :
                    "richonline_logout_payload_must_be_empty"),"logout_rejection_reason_wrong");
            }
            require(rejected==(version==ClientVersion::legacy || !payload.empty()),"logout_acceptance_wrong");
            require(session.state()==LobbyState::closed,"logout_left_session_open");
            session.finish();
        }
        require(cleaned==2 && dispatched==(version==ClientVersion::legacy ? 2 : 0),"logout_cleanup_or_legacy_changed");
    }
    RichLobbySession preauth({"127.0.0.1",0,local_lobby_handshake()},{});
    static_cast<void>(preauth.start());
    static_cast<void>(preauth.feed(encode_frame({759,{113,0,0,0}},{Channel::lobby_c2s,std::nullopt,ClientVersion::richonline})));
    bool rejected=false;
    try { static_cast<void>(preauth.feed(encode_frame({0xffffffffU,{}},{Channel::lobby_c2s,219,ClientVersion::richonline}))); }
    catch (const CodecError& error) { rejected=std::string(error.what())=="invalid_richonline_login_frame"; }
    require(rejected && preauth.state()==LobbyState::closed,"preauth_logout_accepted");
}
void tcp_explicit_logout_cleans_connection_without_reply() {
    Hub hub; std::string logs;
    RichLobbyService service({"127.0.0.1",0,local_lobby_handshake()},[&] { return hub.connect(); },[&](const std::string& line) {
        const std::lock_guard lock(hub.mutex); logs+=line+'\n';
        if (line.starts_with("lobby_listening")) { hub.listening=true; hub.changed.notify_all(); }
    });
    std::exception_ptr failure;
    std::thread worker([&] { try { service.run(); } catch (...) { failure=std::current_exception(); } });
    try {
        { std::unique_lock lock(hub.mutex); require(hub.changed.wait_for(lock,std::chrono::seconds(3),[&] { return hub.listening; }),"logout_listener_missing"); }
        Client client(service.bound_port(),3,"logout");
        client.send(encode_frame({0xffffffffU,{}},{Channel::lobby_c2s,client.key,ClientVersion::richonline}));
        char byte{}; require(recv(client.socket,&byte,1,0)==0,"logout_reply_or_open_socket");
        service.stop(); worker.join();
        if (failure) std::rethrow_exception(failure);
        require(hub.departures["logout"]==1 && !hub.queues.contains("logout") && service.authenticated_sessions()==0,
            "logout_connection_state_leaked");
        require(logs.find("lobby_client_logout")!=logs.npos,"logout_reason_missing");
    } catch (...) { service.stop(); if (worker.joinable()) worker.join(); throw; }
}
}
int main() {
    try { unit_cleanup_and_pre_auth_poll(); tcp_idle_delivery_and_disconnect_cleanup();
        tcp_explicit_logout_cleans_connection_without_reply(); explicit_logout_has_strict_state_and_payload_boundaries();
        std::cout << "lobby delivery tests PASS\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
