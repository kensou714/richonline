#include "richonline_boss_property.hpp"
#include "richonline_boss_stage.hpp"
#include "richonline_boss_landing.hpp"
#include "service.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>

namespace {
using namespace richnet;
constexpr std::uint16_t game_id=0x1234, calendar=0x4567;
void check(bool value,const char* reason) { if (!value) throw std::runtime_error(reason); }
struct Network {
    Network() { WSADATA data{}; check(WSAStartup(MAKEWORD(2,2),&data)==0,"winsock_start_failed"); }
    ~Network() { WSACleanup(); }
};
Bytes request(std::uint16_t opcode,std::uint16_t counter,std::uint32_t argument,std::size_t width=2) {
    Bytes bytes; append_le(bytes,opcode,2); append_le(bytes,counter,2); append_le(bytes,argument,width); return bytes;
}
struct Peer {
    SOCKET socket=INVALID_SOCKET;
    explicit Peer(std::uint16_t port) {
        socket=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        check(socket!=INVALID_SOCKET,"socket_failed");
        try {
            const DWORD timeout=3000;
            for (const auto option : {SO_RCVTIMEO,SO_SNDTIMEO})
                check(setsockopt(socket,SOL_SOCKET,option,reinterpret_cast<const char*>(&timeout),sizeof(timeout))==0,"socket_timeout_failed");
            sockaddr_in address{}; address.sin_family=AF_INET; address.sin_port=htons(port);
            check(inet_pton(AF_INET,"127.0.0.1",&address.sin_addr)==1,"address_invalid");
            check(connect(socket,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"connect_failed");
        } catch (...) { closesocket(socket); throw; }
    }
    ~Peer() { closesocket(socket); }
    Peer(const Peer&)=delete;
    Peer& operator=(const Peer&)=delete;
    void send_frame(const Frame& frame) {
        const auto encoded=encode_frame(frame,{Channel::game_c2s,{},ClientVersion::richonline});
        View left(encoded);
        while (!left.empty()) {
            const auto sent=::send(socket,reinterpret_cast<const char*>(left.data()),static_cast<int>(left.size()),0);
            check(sent>0,"send_failed"); left=left.subspan(static_cast<std::size_t>(sent));
        }
    }
    void send(View plain) { send_frame(richonline_board_frame(plain,{7,-2},Bytes(plain.size()+2,0x91))); }
    Bytes read(std::size_t length) {
        Bytes bytes(length);
        for (std::size_t offset=0;offset<length;) {
            const auto count=recv(socket,reinterpret_cast<char*>(bytes.data()+offset),static_cast<int>(length-offset),0);
            check(count>0,"receive_failed"); offset+=static_cast<std::size_t>(count);
        }
        return bytes;
    }
    Frame receive_frame() {
        auto bytes=read(8); const auto size=read_le(View(bytes).subspan(4,4));
        check(size>=8 && size<=max_frame_total,"frame_length_invalid");
        const auto payload=read(size-8); bytes.insert(bytes.end(),payload.begin(),payload.end());
        return decode_frame(bytes,{Channel::game_s2c,{},ClientVersion::richonline});
    }
    Bytes receive() {
        const auto frame=receive_frame(); check(frame.wire_type==299,"game_envelope_missing");
        const auto envelope=decode_envelope(frame,ClientVersion::richonline);
        check(envelope.inner_type==7 && envelope.mode==-2,"envelope_policy_wrong");
        return decode_inner(envelope.encoded);
    }
    void quiet() {
        fd_set readable; FD_ZERO(&readable); FD_SET(socket,&readable);
        timeval timeout{0,100000};
        check(select(0,&readable,nullptr,nullptr,&timeout)==0,"pending_decision_sent_premature_response_or_turn");
    }
};
RichonlineBossStartup startup(bool boss_owned) {
    RichonlineBossStartup value{{3,25,{},{{1,25,0,true}}},
        {game_id,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
            {{25,233,1,{7,7,7,7,7,7,7,7,7,7},0xb1},{-1,static_cast<std::int16_t>(boss_owned?232:236),1,{},0xc1}}},
        {game_id,calendar,1,{{20000,0,150},{100000,0,0}}},{7,-2}};
    value.room.description.record[36]=3;
    return value;
}
struct Scenario {
    std::atomic<std::int64_t> elapsed{0};
    std::shared_ptr<RichonlineBossProperty> property;
    GameAdmission admission{0,3,25,{1,2,3,4,5,6,7,8},0x8b7a6910,{}};
    std::mutex mutex;
    std::condition_variable changed;
    bool listening=false;
    std::exception_ptr failure;
    std::unique_ptr<GameService> service;
    std::thread worker;
    Scenario(const std::filesystem::path& resources,bool boss_owned,unsigned level) {
        property=std::make_shared<RichonlineBossProperty>(resources,game_id,std::array<std::uint32_t,2>{20000,100000},
            load_richonline_boss_stage(resources,"BS_1_1.emp"));
        property->configure_construction({7,7,7,7,7,7,7,7,7,7});
        property->enable_human_decisions(std::chrono::seconds{5},[this] {
            return RichonlineBossProperty::Clock::time_point{}+std::chrono::milliseconds{elapsed.load()};
        });
        const RichonlineLandingContext precondition{static_cast<std::uint8_t>(boss_owned?1:0),232,33,216,3,boss_owned,2,false};
        check(property->land(precondition).has_value(),"fixture_purchase_not_recognized");
        if (!boss_owned) {
            auto purchase=request(0x20,calendar,0,4); purchase.insert(purchase.end(),{1,0xa5,0x5a,0xc3});
            property->decide(purchase);
        }
        for (unsigned current=0;current<level;++current) {
            check(property->land(precondition).has_value(),"fixture_build_not_recognized");
            if (!boss_owned) {
                property->decide(request(current==0?0x37:0x38,calendar,current==0?11:1));
                if(current>0) property->decide(request(0x39,calendar,0xff));
            }
        }
        service=std::make_unique<GameService>(ServiceOptions{"127.0.0.1",0,ClientVersion::richonline},
            [this,resources,boss_owned] {
                return make_richonline_game_callbacks([this,resources,boss_owned](const GameAdmission& supplied)
                    ->std::optional<RichonlineStartupPlan> {
                    if (supplied!=admission) return {};
                    RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
                        [](std::size_t) { return std::size_t{0}; },
                        [this](const RichonlineLandingContext& context) {
                            if (auto result=property->land(context)) return *result;
                            return resolve_richonline_empty_boss_landing(game_id,context);
                        },[this](View plain) { return property->decide(plain); }};
                    rules.poll=[this] { return property->poll(); };
                    return make_richonline_boss_turns(startup(boss_owned),
                        load_richonline_road_topology(resources/"Map/BS_1_1.emp"),std::move(rules));
                },[](std::size_t size) { return Bytes(size,0x91); });
            },[this](const std::string& line) {
                const std::lock_guard lock(mutex);
                if (line.starts_with("game_transport_listening port=")) listening=true;
                changed.notify_all();
            });
        worker=std::thread([this] {
            try { service->run(); }
            catch (...) { const std::lock_guard lock(mutex); failure=std::current_exception(); changed.notify_all(); }
        });
        try {
            std::unique_lock lock(mutex);
            check(changed.wait_for(lock,std::chrono::seconds{5},[this] { return listening || failure; }),"listener_timeout");
            if (failure) std::rethrow_exception(failure);
        } catch (...) { stop(); throw; }
    }
    ~Scenario() { stop(); }
    void stop() { service->stop(); if (worker.joinable()) worker.join(); }
};
void turn(Peer& peer,std::uint8_t actor) {
    check(peer.receive()==Bytes({0x10,0x40,0x34,0x12,actor,1,0,0xa2}),"next_actor_wrong");
    check(peer.receive()==Bytes({0x0f,0x42,0x34,0x12,0xff,0xff}),"turn_status_missing");
}
void movement(Peer& peer,std::uint16_t start) {
    const auto bytes=peer.receive();
    check(bytes.size()==28 && read_le(View(bytes).first(2))==0x4011 &&
        read_le(View(bytes).subspan(4,2))==start && bytes[7]==1 && bytes[8]==1 && (bytes[11]&3U)==1,
        "real_one_step_route_wrong");
}
void opening(Scenario& scenario,Peer& peer,bool boss_owned) {
    peer.send_frame(encode_game_admission(scenario.admission,ClientVersion::richonline));
    const auto ack=peer.receive_frame(); check(ack.wire_type==1 && ack.payload.empty(),"admission_ack_wrong");
    const auto init=peer.receive(); check(init.size()==52 && read_le(View(init).first(2))==0x4000,"init_missing");
    peer.send(Bytes{1,0}); peer.send(Bytes{0,0});
    const auto sync=peer.receive(); check(sync.size()==36 && read_le(View(sync).first(2))==0x4004,"sync_missing");
    turn(peer,1); movement(peer,boss_owned?232:236);
}
void stop_ack(Peer& peer,std::uint8_t endpoint) {
    check(peer.receive()==Bytes({0x13,0x40,0x34,0x12,endpoint,0}),"owned_landing_stop_ack_missing");
}
void boss_owned_property_completes_over_tcp(const std::filesystem::path& resources,unsigned initial_level) {
    Scenario scenario(resources,true,initial_level); Peer peer(scenario.service->bound_port());
    opening(scenario,peer,true);
    peer.send(request(0x11,calendar+1,231));
    stop_ack(peer,231);
    if (initial_level==0) check(peer.receive()==Bytes({0x3d,0x40,0x34,0x12,11}),"boss_first_construction_response_missing");
    else if (initial_level<5) check(peer.receive()==Bytes({0x3e,0x40,0x34,0x12,1}),"boss_auto_upgrade_response_missing");
    turn(peer,0);
    peer.quiet(); scenario.stop();
    const auto building=scenario.property->building(216);
    check(building && building->kind==11 && building->level==std::min(initial_level+1,5U),"boss_building_level_wrong");
    check(scenario.property->owner(216)==std::optional<std::uint8_t>{1} &&
        scenario.property->cash()==std::array<std::uint32_t,2>{20000,99900},"boss_build_changed_owner_or_charged_again");
}
enum class Decision { accept, cancel, timeout };
void human_owned_property_waits_and_retires_replay(const std::filesystem::path& resources,bool upgrade,Decision decision) {
    Scenario scenario(resources,false,upgrade?1U:0U); Peer peer(scenario.service->bound_port());
    opening(scenario,peer,false);
    peer.send(request(0x11,calendar+1,235)); stop_ack(peer,235); turn(peer,0);
    peer.send(request(0x10,calendar+2,0,4)); movement(peer,233);
    peer.send(request(0x11,calendar+2,232)); stop_ack(peer,232);
    peer.quiet();
    const bool accepts=decision==Decision::accept;
    const auto selection=upgrade?(accepts?1U:0U):(accepts?11U:10U);
    const auto action=request(upgrade?0x38:0x37,calendar+2,selection);
    if (decision==Decision::timeout) scenario.elapsed.store(5000);
    else peer.send(action);
    check(peer.receive()==Bytes({static_cast<std::uint8_t>(upgrade?0x3e:0x3d),0x40,0x34,0x12,
        static_cast<std::uint8_t>(selection)}),"human_build_decision_response_wrong");
    if(upgrade) {
        peer.quiet();
        if(decision==Decision::timeout) scenario.elapsed.store(10000);
        else peer.send(request(0x39,calendar+2,0xff));
        check(peer.receive()==Bytes({0x3f,0x40,0x34,0x12,0xff}),"research_cancel_response_missing");
    }
    turn(peer,1); movement(peer,235);
    peer.send(action);
    peer.send(request(0x11,calendar+3,234)); stop_ack(peer,234); turn(peer,0);
    peer.quiet(); scenario.stop();
    const auto building=scenario.property->building(216);
    check(building && building->level==(upgrade?1U:0U)+(accepts?1U:0U),"human_build_replayed_or_wrong_level");
    check(scenario.property->owner(216)==std::optional<std::uint8_t>{0} &&
        scenario.property->cash()==std::array<std::uint32_t,2>{19900,100000},"human_build_changed_owner_or_charged_again");
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_path_required"); const Network network; const std::filesystem::path resources(argv[1]);
        for (const unsigned level : {0U,1U,5U}) boss_owned_property_completes_over_tcp(resources,level);
        for (const bool upgrade : {false,true})
            for (const auto decision : {Decision::accept,Decision::cancel,Decision::timeout})
                human_owned_property_waits_and_retires_replay(resources,upgrade,decision);
        std::cout<<"PASS encrypted TCP owned property216 BOSS build/upgrade/cap and human wait/accept/cancel/timeout/replay\n";
    } catch (const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
