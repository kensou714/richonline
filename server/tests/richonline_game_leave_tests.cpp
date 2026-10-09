#include "richonline_game_startup.hpp"
#include "richonline_game_registry.hpp"
#include "service.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>

namespace {
using namespace richnet;
void require(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
Bytes filler(std::size_t size) { return Bytes(size, 0x81); }
Bytes request(const Bytes& plain) {
    return encode_frame(richonline_board_frame(plain,{0,-1},filler(plain.size()+2)),
        {Channel::game_c2s,{},ClientVersion::richonline});
}
Bytes response(const Bytes& wire) {
    return decode_inner(decode_envelope(decode_frame(wire,{Channel::game_s2c,{},ClientVersion::richonline}),
        ClientVersion::richonline).encoded);
}
RichonlineStartupPlan startup(std::uint32_t actor, std::atomic_int& released, std::atomic_int& actions) {
    require(actor <= 32767, "fixture_actor_invalid");
    return {
        {0x1234,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
            {{static_cast<std::int16_t>(actor),1,2,{1,2,3,4,5,6,7,8,9,10},0xb1},
             {-1,9,3,{11,12,13,14,15,16,17,18,19,20},0xb2}}},
        {0x1234,0x88774433,100,{{2000,3000,4},{5000,6000,7}}}, {9,-3},
        [] { return std::vector<Bytes>{}; },
        [&](const Envelope299&, View) { ++actions; return std::vector<Bytes>{}; },
        [&] { ++released; }
    };
}
struct Network {
    Network() { WSADATA data{}; require(WSAStartup(MAKEWORD(2,2),&data)==0,"winsock_failed"); }
    ~Network() { WSACleanup(); }
};
struct Client {
    SOCKET socket = INVALID_SOCKET;
    explicit Client(std::uint16_t port) {
        socket=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        require(socket!=INVALID_SOCKET,"socket_failed");
        const DWORD timeout=3000;
        require(setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout))==0,"timeout_failed");
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_port=htons(port);
        require(inet_pton(AF_INET,"127.0.0.1",&address.sin_addr)==1,"address_failed");
        require(connect(socket,reinterpret_cast<const sockaddr*>(&address),sizeof(address))==0,"connect_failed");
    }
    ~Client() { if(socket!=INVALID_SOCKET) closesocket(socket); }
    void send(View bytes) const {
        while(!bytes.empty()) {
            const auto count=::send(socket,reinterpret_cast<const char*>(bytes.data()),static_cast<int>(bytes.size()),0);
            require(count>0,"send_failed"); bytes=bytes.subspan(static_cast<std::size_t>(count));
        }
    }
    Bytes read(std::size_t size) const {
        Bytes bytes(size); std::size_t offset=0;
        while(offset<size) {
            const auto count=recv(socket,reinterpret_cast<char*>(bytes.data()+offset),static_cast<int>(size-offset),0);
            require(count>0,"reply_truncated"); offset+=static_cast<std::size_t>(count);
        }
        return bytes;
    }
    Bytes frame() const {
        auto bytes=read(8);
        const auto total=read_le(View(bytes).subspan(4,4));
        require(total>=8 && total<65536,"reply_size_invalid");
        const auto body=read(total-8); bytes.insert(bytes.end(),body.begin(),body.end()); return bytes;
    }
    void eof() const { char byte{}; require(recv(socket,&byte,1,0)==0,"leave_was_not_graceful_eof"); }
};
struct Running {
    GameService& service; std::exception_ptr error; std::thread thread;
    explicit Running(GameService& value):service(value),thread([this] {
        try { service.run(); } catch(...) { error=std::current_exception(); }
    }) {}
    ~Running() { service.stop(); if(thread.joinable()) thread.join(); }
};

void session_defers_cleanup_until_ack_is_encoded_and_sent() {
    std::atomic_int released=0,actions=0;
    const GameAdmission admission{7,19,25,{1,2,3,4,5,6,7,8},0x8b7a6910,{}};
    GameSession session(ClientVersion::richonline,make_richonline_game_callbacks(
        [&](const GameAdmission&)->std::optional<RichonlineStartupPlan> { return startup(25,released,actions); },filler));
    (void)session.feed(encode_frame(encode_game_admission(admission,ClientVersion::richonline),
        {Channel::game_c2s,{},ClientVersion::richonline}));
    auto input=request({10,0});
    const auto queued=request({0,0}); input.insert(input.end(),queued.begin(),queued.end());
    input.push_back(0xff); // partial trailing frame cannot replace the leave ACK
    const auto replies=session.feed(input);
    require(replies.size()==1 && response(replies[0])==Bytes({6,0x40,0x34,0x12}),"leave_ack_wrong");
    require(session.state()==GameState::departing && released==0 && actions==0,"leave_cleanup_before_send");
    require(session.poll().empty(),"departing_game_polled");
    session.finish(); session.finish();
    require(session.state()==GameState::closed && released==1,"leave_cleanup_not_once");
}

void tcp_ack_before_eof_releases_room_and_allows_restart() {
    std::atomic_int released=0,actions=0;
    std::atomic_uint generation=0;
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& room) {
        const auto& peer=room.participants.front();
        RichonlineGameRedirect redirect{{127,0,0,1},18602,++generation,{1,2,3,4,5,6,7,8}};
        const auto admission=richonline_expected_admission({room.channel,room.key,peer.actor},redirect);
        auto callbacks=make_richonline_game_callbacks(
            [&,actor=peer.actor](const GameAdmission&)->std::optional<RichonlineStartupPlan> {
                return startup(actor,released,actions);
            },filler);
        require(callbacks.authorize_admission(admission),"fixture_authorization_failed");
        return std::vector<RichonlineGamePlan>{{peer.connection,peer.actor,redirect,
            [callbacks,admission] { return callbacks.admitted(admission); },
            [callbacks,admission](const Envelope299& envelope,View plain) { return callbacks.message(admission,envelope,plain); },
            [callbacks,admission] { callbacks.disconnected(admission); },
            [callbacks,admission] { return callbacks.poll(admission); }}};
    },9,std::chrono::seconds(30));
    std::mutex mutex; std::condition_variable condition; bool listening=false;
    std::vector<std::string> logs;
    GameService service({"127.0.0.1",0,ClientVersion::richonline},[&] { return registry.callbacks(); },
        [&](const std::string& line) {
            const std::lock_guard lock(mutex); logs.push_back(line);
            if(service.bound_port()!=0) { listening=true; condition.notify_one(); }
        });
    Running running(service);
    { std::unique_lock lock(mutex); require(condition.wait_for(lock,std::chrono::seconds(5),[&] { return listening; }),"listen_timeout"); }

    RichonlineRoomDirectory rooms({7,8});
    Bytes profile(272); profile[0]=25;
    (void)rooms.enter(10,25,{7,profile});
    RichonlineRoomDescription description{};
    description.record[0]='r'; description.record[76]='s'; description.record[124]=1;
    description.record[36]=2; description.record[40]=1; description.record[72]=1;
    description.record[32]=0x40; description.record[120]=88; description.extension=Bytes(88,0xa5);
    Bytes create(description.record.begin(),description.record.end());
    create.insert(create.end(),description.extension.begin(),description.extension.end());
    (void)rooms.receive(10,25,{3,create});
    const auto room_key=*rooms.room_key(10);

    // Another room stays registered while this client's game exits.
    RichonlineRoomSnapshot other{77,26,description,{{11,26,0,true}},9};
    (void)registry.prepare(other);
    for(int round=0;round<2;++round) {
        (void)rooms.receive(10,25,{5,{}});
        auto snapshot=rooms.ready_game(10); require(snapshot.has_value(),"cannot_start_again"); snapshot->channel=9;
        const auto redirects=registry.prepare(*snapshot); rooms.set_game_pending(10,true);
        require(redirects.size()==1 && redirects.front().frame.wire_type==22,"redirect_missing");
        const RichonlineGameRedirect redirected{{127,0,0,1},18602,generation.load(),{1,2,3,4,5,6,7,8}};
        const auto admission=richonline_expected_admission({9,room_key,25},redirected);
        const Client client(service.bound_port());
        client.send(encode_frame(encode_game_admission(admission,ClientVersion::richonline),{Channel::game_c2s,{},ClientVersion::richonline}));
        require(decode_frame(client.frame(),{Channel::game_s2c,{},ClientVersion::richonline}).wire_type==1,"admission_ack_missing");
        require(read_le(View(response(client.frame())).first(2))==0x4000,"startup_missing");
        client.send(request({0,0}));
        require(read_le(View(response(client.frame())).first(2))==0x4004,"snapshot_missing");
        client.send(request({10,0}));
        require(response(client.frame())==Bytes({6,0x40,0x34,0x12}),"tcp_leave_ack_missing");
        client.eof();
        require(!registry.has_room(9,room_key) && registry.has_room(9,77),"leave_cancelled_wrong_room");
        require(released==round+1,"duplicate_or_missing_release");
        const auto reset=rooms.game_finished(room_key);
        require(!reset.empty() && !rooms.ready_game(10),"lobby_room_not_reset");
        require(rooms.game_finished(room_key).empty(),"room_reset_not_idempotent");
    }
    (void)rooms.receive(10,25,{6,{1,0,0,0}});
    require(!rooms.room_key(10),"lobby_leave_not_applied");
    (void)rooms.receive(10,25,{3,create});
    require(rooms.room_key(10).has_value(),"cannot_create_new_room_after_exit");
    service.stop(); running.thread.join(); if(running.error) std::rethrow_exception(running.error);
    {
        const std::lock_guard lock(mutex);
        std::size_t normal=0;
        for(const auto& line:logs) {
            if(line.find("game_connection_closed")!=std::string::npos) {
                require(line.find("reason=game_leave_completed")!=std::string::npos,"normal_leave_logged_as_failure"); ++normal;
            }
        }
        require(normal==2,"normal_leave_log_count_wrong");
    }
    registry.shutdown(); require(released==3 && actions==0,"remaining_room_cleanup_wrong");
}
}
int main() {
    try { const Network network; session_defers_cleanup_until_ack_is_encoded_and_sent();
        tcp_ack_before_eof_releases_room_and_allows_restart();
        std::cout<<"richonline_game_leave_tests passed\n";
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
