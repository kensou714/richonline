#include "richonline_boss_property.hpp"
#include "richonline_boss_stage.hpp"
#include "richonline_boss_landing.hpp"
#include "richonline_npc_session.hpp"
#include "original_game_values.hpp"
#include "richonline_combat_bridge.hpp"
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
    std::optional<std::int16_t> preliminary_boss_endpoint;
    std::int8_t temple_npc=-1;
    std::int16_t temple_endpoint=-1;
    std::shared_ptr<RichonlineNpcSession> npcs;
    std::shared_ptr<RichonlineGameLedger> temple_ledger;
    bool temple_aura=false;
    bool audit_strength=false;
    std::array<RichonlineActorStatus,2> observed_status{};
    bool normal_cards=false;
    std::shared_ptr<RichonlineBossCards> normal_hand;
    std::shared_ptr<RichonlineGroundObjects> normal_ground;
    Scenario(const std::filesystem::path& resources,bool boss_owned,unsigned level,bool card_flow=false):normal_cards(card_flow) {
        temple_ledger=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{20000,0,150,{}},{100000,0,0,{}}});
        property=std::make_shared<RichonlineBossProperty>(resources,game_id,temple_ledger,
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
        launch(resources,startup(boss_owned),"BS_1_1.emp");
    }
    Scenario(const std::filesystem::path& resources,const char* map,std::uint32_t category,std::int16_t endpoint,
        bool visitor_boss,std::int8_t npc=-1,bool friendly=false,int upgrade=-1,unsigned temple_level=0) {
        temple_npc=npc;temple_endpoint=endpoint;
        temple_aura=temple_level!=0;
        audit_strength=temple_level!=0 && npc!=-1;
        auto stage=load_richonline_boss_stage(resources,map,category);
        if(friendly) stage.scenario_caps[5]=static_cast<std::int8_t>(upgrade<0?1:5);
        if(temple_level) {
            stage.scenario_caps[5]=static_cast<std::uint8_t>(temple_level+(upgrade>=0?1:0));
            stage.boss.building_skills[5]=7;
        }
        const auto topology=load_richonline_road_topology(resources/"Map"/map);
        temple_ledger=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{20000,0,150,{}},{100000,0,0,{}}});
        property=std::make_shared<RichonlineBossProperty>(resources,game_id,temple_ledger,stage);
        property->enable_human_decisions(std::chrono::seconds{5},[]{return RichonlineBossProperty::Clock::time_point{};});
        if((friendly && upgrade>=0) || temple_level) {
            std::array<std::int8_t,10> skills{};skills.fill(7);property->configure_construction(skills);
        }
        const auto& target=topology.cell(endpoint);
        const auto degree=static_cast<std::uint8_t>(std::count_if(target.neighbors.begin(),target.neighbors.end(),
            [](const auto& neighbor){return neighbor.has_value();}));
        check(property->building(target.property_ref)->kind==16,"fixture_expected_prebuilt_temple");
        const auto visitor=static_cast<std::uint8_t>(visitor_boss?1:0);
        const auto owner=static_cast<std::uint8_t>(friendly?visitor:1-visitor);
        check(property->land({owner,endpoint,target.static_type,target.property_ref,3,owner==1,degree,false}).has_value(),
            "fixture_temple_purchase_missing");
        if(owner==0) {
            auto purchase=request(0x20,calendar,0,4);purchase.insert(purchase.end(),{1,0,0,0});property->decide(purchase);
        }
        if(temple_level) {
            property->enable_temple_possession(10,true,{true,true,true,true});
            while(property->building(target.property_ref)->level<temple_level) {
                const auto previous_level=property->building(target.property_ref)->level;
                check(property->land({owner,endpoint,target.static_type,target.property_ref,3,owner==1,degree,false}).has_value(),
                    "fixture_temple_upgrade_missing");
                if(owner==0) property->decide(request(0x38,calendar,1));
                check(property->building(target.property_ref)->level>previous_level,"fixture_temple_upgrade_made_no_progress");
            }
        }
        auto initial=startup(false);
        bool found=false;
        for(std::uint8_t direction=0;direction<4;++direction) if(target.neighbors[direction]) {
            initial.init.participants[visitor].position=*target.neighbors[direction];
            initial.init.participants[visitor].direction=static_cast<std::uint8_t>((direction+2U)%4U);
            found=true;break;
        }
        check(found,"fixture_temple_has_no_approach");
        const auto other=std::find_if(topology.cells().begin(),topology.cells().end(),[&](const auto& cell) {
            constexpr std::array<std::int16_t,8> supported{-1,5,6,7,8,10,41,42};
            return cell.walkable && cell.position!=endpoint && cell.position!=initial.init.participants[visitor].position &&
                (!temple_aura || !visitor_boss || cell.static_type==-1 || (cell.static_type>=5 && cell.static_type<=7)) &&
                cell.property_ref==-1 && std::find(supported.begin(),supported.end(),cell.static_type)!=supported.end() &&
                std::any_of(cell.neighbors.begin(),cell.neighbors.end(),[&](const auto& neighbor) {
                    return neighbor && *neighbor!=endpoint && *neighbor!=initial.init.participants[visitor].position;
                });
        });
        check(other!=topology.cells().end(),"fixture_other_actor_position_missing");
        initial.init.participants[1-visitor].position=other->position;
        if(!visitor_boss || temple_aura) {
            if(!visitor_boss) preliminary_boss_endpoint=other->position;
            for(std::uint8_t direction=0;direction<4;++direction) if(other->neighbors[direction] &&
                *other->neighbors[direction]!=endpoint && *other->neighbors[direction]!=initial.init.participants[visitor].position) {
                initial.init.participants[1-visitor].position=*other->neighbors[direction];
                initial.init.participants[1-visitor].direction=static_cast<std::uint8_t>((direction+2U)%4U);break;
            }
        }
        launch(resources,std::move(initial),map);
    }
    void launch(const std::filesystem::path& resources,RichonlineBossStartup initial,std::string map) {
        service=std::make_unique<GameService>(ServiceOptions{"127.0.0.1",0,ClientVersion::richonline},
            [this,resources,initial,map] {
                return make_richonline_game_callbacks([this,resources,initial,map](const GameAdmission& supplied)
                    ->std::optional<RichonlineStartupPlan> {
                    if (supplied!=admission) return {};
                    RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
                        [](std::size_t) { return std::size_t{0}; },
                        [this](const RichonlineLandingContext& context) {
                            observed_status[context.actor_slot]=context.actor_status;
                            if(audit_strength && context.position!=temple_endpoint) {
                                Bytes stop{0x13,0x40,0x34,0x12};
                                append_le(stop,static_cast<std::uint16_t>(context.position),2);
                                return RichonlineLandingResult{{std::move(stop)},RichonlineLandingProgress::complete};
                            }
                            if (auto result=property->land(context)) return *result;
                            if(temple_aura && !context.synthetic_actor)
                                return RichonlineBossLandingState(game_id,temple_ledger).land(context);
                            return resolve_richonline_empty_boss_landing(game_id,context);
                        },[this](View plain) { return property->decide(plain); }};
                    rules.poll=[this] { return property->poll(); };
                    if(normal_cards) {
                        normal_hand=std::make_shared<RichonlineBossCards>(
                            std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(resources)),game_id,
                            RichonlineBossCardPolicy{map,17,1038,{0,0}});
                        RichonlineChanceInventory hand{};hand[0]={1051,3};hand[1]={1062,2};hand[2]={1043,2};hand[3]={1044,2};
                        normal_hand->commit_inventory(hand);
                        const auto topology=load_richonline_road_topology(resources/"Map"/map);
                        std::vector<std::int16_t> roads;
                        for(const auto& cell:topology.cells()) if(cell.walkable) roads.push_back(cell.position);
                        normal_ground=std::make_shared<RichonlineGroundObjects>(std::move(roads));
                        RichonlineCombatWorld world;
                        world.width=static_cast<std::uint16_t>(topology.width());world.height=static_cast<std::uint16_t>(topology.height());
                        world.resources={3000,4000,5000,1000,1500,3,2,1,2,2};
                        world.step=[topology](std::int16_t p,std::uint8_t d){return topology.cell(p).neighbors.at(d);};
                        world.targets=[](std::uint8_t,RichonlineCombatEffect,const auto&){return std::vector<std::int16_t>{232};};
                        world.card_targets=world.targets;
                        world.resolve_terms=[](const auto&,const auto&){return RichonlineCombatWorld::ResolvedTerms{{},{},0,0};};
                        world.building=[this](const auto& b,auto effect){return property->combat_building_effect(b,effect);};
                        rules.combat=std::make_shared<RichonlineCombatBridge>(game_id,temple_ledger,normal_hand,normal_ground,property,std::move(world),RichonlineBossCombatPolicy{});
                        rules.combat_random=[] {return RichonlineBossAttackRandomness{{0,0,0,0},[](std::size_t){return std::size_t{0};}};};
                        rules.combat_capabilities=[](std::uint8_t,const auto&){return RichonlineCombatCapabilities{true,false,false,false,true};};
                        rules.terminal=[](const auto&)->RichonlineTurnTerminalResult {throw CodecError("normal_card_unexpected_terminal");};
                        rules.npc_landing_preflight=[](const auto&){};
                        rules.cards=normal_hand;rules.ground=normal_ground;rules.ledger=temple_ledger;rules.property=property;
                        rules.ground_card_visible=[](std::uint8_t,std::int16_t,std::int16_t){return false;};
                        auto raw=std::make_shared<RichonlineRawAuthority>(2,game_id);
                        raw->initialize_game();raw->initialize_actor(0);raw->initialize_actor(1);
                        rules.timed_bombs=std::make_shared<const RichonlineTimedBombTurnPolicy>(RichonlineTimedBombTurnPolicy{
                            std::make_shared<const RichonlineTimedBombRules>(RichonlineTimedBombRules::load(resources)),0xa7,
                            [raw](std::uint8_t mover,std::int16_t position) {
                                return raw->timed_bomb_step_context(mover,position);
                            }});
                    }
                    if(temple_npc!=-1 || temple_aura) {
                        const auto chance=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(resources));
                        auto cards=std::make_shared<RichonlineBossCards>(chance,game_id,
                            RichonlineBossCardPolicy{map,map=="V_BS_1_1.emp"?2:17,1038,{0,0}});
                        auto ledger=temple_ledger;
                        auto ground=std::make_shared<RichonlineGroundObjects>(std::vector<std::int16_t>{temple_endpoint});
                        RichonlineNpcSessionPolicy policy{{temple_npc==-1?0U:1U,0,0,3,3,
                            {temple_npc==-1?std::int8_t{3}:temple_npc},0,0,0,0,false},17,{1038,1039},{25,-1},
                            {load_richonline_npc_affix(resources,0),load_richonline_npc_affix(resources,1)},"fixture-zero-transfer",
                            [](std::uint8_t,std::int8_t,const auto&){return std::int16_t{0};}};
                        if(temple_aura) {
                            policy.badluck=RichonlineNpcBadluckPolicy{load_richonline_npc_affix(resources,2),"fixture-empty-loss",
                                [](const auto&) {return std::array<std::int8_t,4>{-1,-1,-1,-1};}};
                            policy.temple_aura_affix=std::array{load_richonline_npc_affix(resources,4),load_richonline_npc_affix(resources,6)};
                            rules.npc_aura=RichonlineNpcAuraRules::load(resources);
                            auto raw=std::make_shared<RichonlineRawAuthority>(2,game_id);
                            raw->initialize_game();raw->initialize_actor(0);raw->initialize_actor(1);
                            rules.npc_aura_raw_actor=[raw](std::uint8_t actor){return raw->actor(actor);};
                            rules.terminal=[](const RichonlineTurnTerminalContext&)->RichonlineTurnTerminalResult {
                                throw CodecError("fixture_unexpected_bankruptcy");
                            };
                        }
                        npcs=std::make_shared<RichonlineNpcSession>(game_id,map,RichonlineNpcRules::load(resources),chance,
                            std::make_shared<const RichonlineChanceEventTable>(RichonlineChanceEventTable::load(resources)),
                            ledger,cards,ground,policy);
                        property->enable_temple_possession(static_cast<std::uint8_t>(load_original_game_values(resources/"Data/GValue.kpd").require(37)),temple_aura,
                            {true,true,policy.badluck.has_value(),true});
                        rules.npcs=npcs;rules.cards=cards;rules.ledger=ledger;
                        rules.npc_landing_preflight=[this](const RichonlineLandingContext& context) {
                            if(audit_strength && context.position!=temple_endpoint) return;
                            if(temple_aura && !context.synthetic_actor && !property->validate_landing(context)) {
                                RichonlineBossLandingState(game_id,temple_ledger).validate_landing(context);return;
                            }
                            if(!property->validate_landing(context))
                                static_cast<void>(resolve_richonline_empty_boss_landing(game_id,context));
                        };
                    }
                    return make_richonline_boss_turns(initial,
                        load_richonline_road_topology(resources/"Map"/map),std::move(rules));
                },[](std::size_t size) { return Bytes(size,0x91); });
            },[this](const std::string& line) {
                const std::lock_guard lock(mutex);
                if(line.find("error")!=std::string::npos || line.find("rejected")!=std::string::npos ||
                    line.find("reason=richonline_")!=std::string::npos)
                    std::cerr<<line<<'\n';
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
    auto status=peer.receive();
    if(actor==1 && status==Bytes({0x1e,0x40,0x34,0x12})) status=peer.receive();
    if(status!=Bytes({0x0f,0x42,0x34,0x12,0xff,0xff}))
        throw std::runtime_error("turn_status_missing actor="+std::to_string(actor)+
            " opcode="+std::to_string(read_le(View(status).first(2))));
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
void roadblock_early_stop_over_tcp(const std::filesystem::path& resources) {
    Scenario scenario(resources,false,0,true);Peer peer(scenario.service->bound_port());opening(scenario,peer,false);
    peer.send(request(0x11,calendar+1,235));stop_ack(peer,235);turn(peer,0);
    auto hand=scenario.normal_hand->inventory();hand[4]={1038,1};scenario.normal_hand->commit_inventory(hand);
    const auto funds=scenario.temple_ledger->snapshot(0);
    peer.send(Bytes{108,0,0x69,0x45,2,0,232,0});
    check(peer.receive()==Bytes({0xbc,0x40,0x34,0x12,2,0,232,0}),"roadblock_stop_placement_failed");
    peer.send(Bytes{108,0,0x69,0x45,2,0,231,0});
    check(peer.receive()==Bytes({0xbc,0x40,0x34,0x12,2,0,231,0}),"roadblock_future_placement_failed");
    peer.send(Bytes{103,0,0x69,0x45,4,0,6,0,0,0,0,0});
    check(peer.receive()==Bytes({0xb7,0x40,0x34,0x12,4,0}),"roadblock_controlled_die_response_wrong");
    const auto move=peer.receive();
    check(read_le(View(move).first(2))==0x4011 && move[8]==6 && move[7]>=6,"roadblock_wire_route_truncated");
    peer.send(request(0x11,calendar+2,232));stop_ack(peer,232);peer.quiet();
    peer.send(request(0x37,calendar+2,10));
    check(peer.receive()==Bytes({0x3d,0x40,0x34,0x12,10}),"roadblock_landing_decision_failed");
    turn(peer,1);movement(peer,235);
    peer.send(request(0x11,calendar+3,234));stop_ack(peer,234);turn(peer,0);peer.quiet();scenario.stop();
    check(!scenario.normal_ground->snapshot().objects.contains(232) &&
        scenario.normal_ground->snapshot().objects.at(231)==RichonlineGroundObject{11,0,255},
        "roadblock_stop_consumed_unvisited_object");
    check(scenario.normal_hand->inventory()[2]==RichonlineChanceCardSlot{} &&
        scenario.normal_hand->inventory()[4]==RichonlineChanceCardSlot{} &&
        scenario.temple_ledger->snapshot(0).funds==funds.funds,"roadblock_stop_changed_funds_or_card_count");
    std::cout<<"PASS TCP roadblock: die6 -> stop232 -> build cancel -> next two turns; future roadblock231 retained\n";
}
void normal_cards_complete_over_tcp(const std::filesystem::path& resources) {
    Scenario scenario(resources,false,0,true);Peer peer(scenario.service->bound_port());opening(scenario,peer,false);
    peer.send(request(0x11,calendar+1,235));stop_ack(peer,235);turn(peer,0);peer.quiet();
    const auto boss=scenario.temple_ledger->snapshot(1);
    scenario.temple_ledger->adjust(1,boss,{19-static_cast<std::int64_t>(boss.funds.cash),19,0,0});
    const auto human=scenario.temple_ledger->snapshot(0);
    peer.send(Bytes{114,0,0x69,0x45,0,0,1,0});
    check(peer.receive()==Bytes({0xc2,0x40,0x34,0x12,0,0,1,0}),"tax_card_TCP_wire_wrong");peer.quiet();
    check(scenario.temple_ledger->snapshot(0).funds.cash==human.funds.cash+1 &&
        *scenario.temple_ledger->snapshot(0).funds.deposit==1 && scenario.temple_ledger->snapshot(1).funds.cash==18 &&
        *scenario.temple_ledger->snapshot(1).funds.deposit==18,"tax_card_must_truncate_each_account_separately");
    const auto taxed=scenario.temple_ledger->snapshot(1);
    scenario.temple_ledger->adjust(1,taxed,{-18,-18,0,0});
    peer.send(Bytes{114,0,0x69,0x45,0,0,1,0});
    check(peer.receive()==Bytes({0xc2,0x40,0x34,0x12,0,0,1,0}),"zero_tax_card_failed_or_bankrupt");
    for(const std::uint8_t tile:{std::uint8_t{216},std::uint8_t{215}}) {
        peer.send(Bytes{123,0,0x69,0x45,1,0,tile,0});
        check(peer.receive()==Bytes({0xcb,0x40,0x34,0x12,1,0,tile,0}),"house_card_TCP_footprint_wire_wrong");
    }
    peer.send(Bytes{108,0,0x69,0x45,2,0,234,0});
    check(peer.receive()==Bytes({0xbc,0x40,0x34,0x12,2,0,234,0}),"roadblock_card_TCP_wire_wrong");
    peer.send(Bytes{109,0,0x69,0x45,3,0,232,0});
    check(peer.receive()==Bytes({0xbd,0x40,0x34,0x12,3,0,232,0}),"mine_card_TCP_wire_wrong");
    for(const Bytes packet:std::vector<Bytes>{{108,0,0x69,0x45,2,0,234,0},{109,0,0x69,0x45,3,0,232,0},
        {114,0,0x69,0x45,0,0,0,0},{123,0,0x69,0x45,1,0,0,0}}) {
        peer.send(packet);check(peer.receive()==Bytes({0x0b,0x40,0x34,0x12,1}),"normal_card_refusal_disconnected");
    }
    peer.send(request(0x10,calendar+2,0,4));movement(peer,233);peer.quiet();scenario.stop();
    check(scenario.normal_ground->snapshot().objects.at(234)==RichonlineGroundObject{11,0,255} &&
        scenario.normal_ground->snapshot().objects.at(232)==RichonlineGroundObject{12,0,3},"ground_card_TCP_authority_wrong");
    check(scenario.property->building(216)==RichonlineBossProperty::Building{11,2} &&
        scenario.temple_ledger->snapshot(0).funds.cash==human.funds.cash+1,"house_card_charged_cash_or_lost_kind");
    const auto hand=scenario.normal_hand->inventory();
    check(hand[0]==RichonlineChanceCardSlot{1051,1} && hand[1]==RichonlineChanceCardSlot{} &&
        hand[2]==RichonlineChanceCardSlot{1043,1} && hand[3]==RichonlineChanceCardSlot{1044,1},
        "normal_card_success_or_refusal_consumption_wrong");
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
void opponent_prebuilt_temple_completes_over_tcp(const std::filesystem::path& resources,
    const char* map,std::uint32_t category,std::int16_t endpoint,bool visitor_boss,std::int8_t npc=-1,
    bool friendly=false,int upgrade=-1,unsigned temple_level=0) {
    Scenario scenario(resources,map,category,endpoint,visitor_boss,npc,friendly,upgrade,temple_level);
    const auto before=scenario.property->combat_snapshot(); const auto cash=scenario.property->cash();
    Peer peer(scenario.service->bound_port());
    peer.send_frame(encode_game_admission(scenario.admission,ClientVersion::richonline));
    const auto ack=peer.receive_frame();check(ack.wire_type==1 && ack.payload.empty(),"temple_admission_ack_wrong");
    const auto init=peer.receive();check(read_le(View(init).first(2))==0x4000,"temple_init_missing");
    peer.send(Bytes{1,0});peer.send(Bytes{0,0});
    const auto sync=peer.receive();check(read_le(View(sync).first(2))==0x4004,"temple_sync_missing");
    if(npc!=-1) {
        const auto spawned=peer.receive();
        check(read_le(View(spawned).first(2))==0x401c,"temple_initial_npc_missing");
    }
    turn(peer,1);
    auto move=peer.receive();check(read_le(View(move).first(2))==0x4011,"temple_move_missing");
    if(!visitor_boss) {
        peer.send(request(0x11,calendar+1,static_cast<std::uint16_t>(*scenario.preliminary_boss_endpoint)));
        Bytes preliminary_stop{0x13,0x40,0x34,0x12};
        append_le(preliminary_stop,static_cast<std::uint16_t>(*scenario.preliminary_boss_endpoint),2);
        check(peer.receive()==preliminary_stop,"temple_preliminary_stop_missing");turn(peer,0);
        peer.send(request(0x10,calendar+2,0,4));move=peer.receive();
        check(read_le(View(move).first(2))==0x4011,"human_temple_move_missing");
    }
    peer.send(request(0x11,static_cast<std::uint16_t>(calendar+(visitor_boss?1:2)),static_cast<std::uint16_t>(endpoint)));
    Bytes stop{0x13,0x40,0x34,0x12};append_le(stop,static_cast<std::uint16_t>(endpoint),2);
    check(peer.receive()==stop,"temple_stop_missing");
    if(npc==3 && !visitor_boss)
        check(peer.receive()==Bytes({0x23,0x40,0x34,0x12,0x0e,4,0x0f,4}),"temple_ground_fortune_reward_missing");
    if(npc==0 || npc==1) {
        if(!visitor_boss) {
            peer.quiet();
            peer.send(request(0x22,calendar+2,1));
        }
        const auto money=peer.receive();
        check(money.size()==7 && read_le(View(money).first(2))==0x4022 && read_le(View(money).subspan(4,2))==0,
            "temple_ground_roulette_reply_missing");
    }
    if(friendly && upgrade>=0) {
        if(!visitor_boss) {
            peer.quiet();peer.send(request(0x38,calendar+2,static_cast<std::uint32_t>(upgrade)));
        }
        check(peer.receive()==Bytes({0x3e,0x40,0x34,0x12,static_cast<std::uint8_t>(upgrade)}),
            "own_temple_upgrade_reply_wrong");
    }
    turn(peer,static_cast<std::uint8_t>(visitor_boss?0:1));
    std::optional<Bytes> next_move;
    if(!visitor_boss) {
        next_move=peer.receive();check(read_le(View(*next_move).first(2))==0x4011,"temple_following_boss_move_missing");
    }
    if(temple_level) {
        const auto topology=load_richonline_road_topology(resources/"Map"/map);
        const auto visitor=static_cast<std::uint8_t>(visitor_boss?1:0);
        const auto counter=static_cast<std::uint16_t>(calendar+(visitor_boss?1:2));
        const auto finish_move=[&](const Bytes& movement,std::uint16_t identity,bool human) {
            check(read_le(View(movement).first(2))==0x4011,"strength_followup_move_missing");
            const auto start=static_cast<std::int16_t>(read_le(View(movement).subspan(4,2)));
            const auto direction=static_cast<std::uint8_t>(movement[11]&3U);
            const auto end=topology.cell(start).neighbors[direction];check(end.has_value(),"strength_followup_route_invalid");
            peer.send(request(0x11,identity,static_cast<std::uint16_t>(*end)));
            Bytes stop{0x13,0x40,0x34,0x12};append_le(stop,static_cast<std::uint16_t>(*end),2);
            check(peer.receive()==stop,"strength_followup_stop_wrong");
            const auto& cell=topology.cell(*end);
            if(human && std::count_if(cell.neighbors.begin(),cell.neighbors.end(),[](const auto& n){return n.has_value();})>2) {
                std::uint8_t chosen=0;
                while(chosen<4 && (!cell.neighbors[chosen] || chosen==(direction+2U)%4U)) ++chosen;
                check(chosen<4,"strength_followup_junction_missing");
                peer.send(request(0x34,identity,chosen));
                check(peer.receive()==Bytes({0x35,0x40,0x34,0x12,chosen}),"strength_followup_junction_wrong");
            }
        };
        if(visitor_boss) {peer.send(request(0x10,counter+1,0,4));next_move=peer.receive();}
        finish_move(*next_move,static_cast<std::uint16_t>(counter+1),visitor_boss);
        turn(peer,visitor);
        if(!visitor_boss) peer.send(request(0x10,counter+2,0,4));
        const auto second_move=peer.receive();
        finish_move(second_move,static_cast<std::uint16_t>(counter+2),!visitor_boss);
        turn(peer,static_cast<std::uint8_t>(1-visitor));
        if(!visitor_boss) check(read_le(View(peer.receive()).first(2))==0x4011,"strength_third_boss_move_missing");
    }
    peer.quiet();scenario.stop();
    auto expected_buildings=before.buildings;
    const auto topology=load_richonline_road_topology(resources/"Map"/map);
    if(upgrade==1) for(auto& building:expected_buildings)
        if(building.property==static_cast<std::uint32_t>(topology.cell(endpoint).property_ref)) ++building.level;
    check(scenario.property->cash()==cash && scenario.property->combat_snapshot().buildings==expected_buildings,
        "temple_tcp_no_effect_changed_property_or_money");
    if(npc!=-1) {
        const auto level=scenario.property->building(topology.cell(endpoint).property_ref)->level;
        const auto affix=load_richonline_npc_affix(resources,npc);
        const bool beneficial=npc==3 || npc==0;
        const auto maximum=load_original_game_values(resources/"Data/GValue.kpd").require(37);
        const int remaining=beneficial!=friendly ? (level<4 ? static_cast<int>(affix)-level-1 : 0) :
            std::min(static_cast<int>(affix)+(level<4 ? 0 : level-3),maximum);
        RichonlineActorStatus status;if(remaining>0)status.possession=npc;
        const auto visitor=static_cast<std::uint8_t>(visitor_boss?1:0);
        if(temple_level) {
            status=scenario.observed_status[visitor];
            check(status.possession==npc && status.possession_strength1740==20 && status.possession_multiplier1744==0.2F,
                "encrypted_temple_strength_not_in_authoritative_continuation");
        }
        const auto identity=temple_level?2U:1U;
        const auto turns_remaining=remaining-(temple_level?1:0);
        check(scenario.npcs->actor_begin(visitor,identity,status).duplicate,"temple_tcp_same_turn_was_ticked_again");
        for(int next=1;next<=turns_remaining;++next)
            check(scenario.npcs->actor_begin(visitor,static_cast<std::uint64_t>(next)+identity,status).expired.has_value()==(next==turns_remaining),
                "temple_tcp_duration_not_committed_by_turn_owner");
        if(temple_level) check(!status.possession && status.possession_strength1740==0 && status.possession_multiplier1744==0.2F,
            "encrypted_temple_strength_expiry_wrong");
    }
}
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
void temple_summon_and_aura_over_tcp(const std::filesystem::path& resources,const char* map,
    std::uint32_t category,std::int16_t endpoint,bool visitor_boss,bool friendly,unsigned level,int upgrade) {
    std::cout<<"temple aura map="<<map<<" boss="<<visitor_boss<<" friendly="<<friendly<<" level="<<level<<" upgrade="<<upgrade<<'\n';
    Scenario scenario(resources,map,category,endpoint,visitor_boss,-1,friendly,upgrade,level);
    const auto topology=load_richonline_road_topology(resources/"Map"/map);
    const auto before=scenario.temple_ledger->snapshot(0);const auto boss_before=scenario.temple_ledger->snapshot(1);
    const auto visitor=static_cast<std::uint8_t>(visitor_boss?1:0);
    Peer peer(scenario.service->bound_port());
    peer.send_frame(encode_game_admission(scenario.admission,ClientVersion::richonline));
    check(peer.receive_frame().wire_type==1,"summon_admission_ack_missing");
    check(read_le(View(peer.receive()).first(2))==0x4000,"summon_init_missing");
    peer.send(Bytes{1,0});peer.send(Bytes{0,0});
    check(read_le(View(peer.receive()).first(2))==0x4004,"summon_sync_missing");
    turn(peer,1);check(read_le(View(peer.receive()).first(2))==0x4011,"summon_first_move_missing");
    const auto stop_at=[&](std::int16_t position) {
        Bytes stop{0x13,0x40,0x34,0x12};append_le(stop,static_cast<std::uint16_t>(position),2);
        check(peer.receive()==stop,"summon_stop_wrong");
    };
    if(!visitor_boss) {
        peer.send(request(0x11,calendar+1,static_cast<std::uint16_t>(*scenario.preliminary_boss_endpoint)));
        stop_at(*scenario.preliminary_boss_endpoint);turn(peer,0);
        peer.send(request(0x10,calendar+2,0,4));check(read_le(View(peer.receive()).first(2))==0x4011,"summon_human_move_missing");
    }
    const auto source_counter=static_cast<std::uint16_t>(calendar+(visitor_boss?1:2));
    peer.send(request(0x11,source_counter,static_cast<std::uint16_t>(endpoint)));stop_at(endpoint);
    if(upgrade>=0) {
        if(!visitor_boss) {peer.quiet();peer.send(request(0x38,source_counter,static_cast<std::uint32_t>(upgrade)));}
        check(peer.receive()==Bytes({0x3e,0x40,0x34,0x12,static_cast<std::uint8_t>(upgrade)}),"summon_upgrade_reply_wrong");
    }
    const auto final_level=level+(upgrade==1?1U:0U);
    const bool summoned=final_level>=5;
    const auto npc=static_cast<std::int8_t>(final_level>=7?(friendly?0:1):final_level==6?(friendly?3:2):(friendly?4:6));
    if(summoned && npc==3 && !visitor_boss)
        check(peer.receive()==Bytes({0x23,0x40,0x34,0x12,0x0e,4,0x0f,4}),"temple_fortune_reward_wrong");
    if(summoned && npc==2 && !visitor_boss)
        check(peer.receive()==Bytes({0x24,0x40,0x34,0x12,0xff,0xff,0xff,0xff}),"temple_badluck_reply_wrong");
    if(summoned && (npc==0 || npc==1)) {
        if(!visitor_boss) {
            peer.quiet();peer.send(request(0x22,source_counter,1));
        }
        check(peer.receive()==Bytes({0x22,0x40,0x34,0x12,0,0,0}),"temple_money_reply_wrong");
    }
    turn(peer,static_cast<std::uint8_t>(1-visitor));
    if(visitor_boss) peer.send(request(0x10,source_counter+1,0,4));
    const auto movement=peer.receive();check(read_le(View(movement).first(2))==0x4011,"summon_next_move_missing");
    const auto start=static_cast<std::int16_t>(read_le(View(movement).subspan(4,2)));
    const auto direction=static_cast<std::uint8_t>(movement[11]&3U);
    const auto other_end=topology.cell(start).neighbors[direction];check(other_end.has_value(),"summon_other_route_invalid");
    if(upgrade>=0 && !visitor_boss) peer.send(request(0x38,source_counter,static_cast<std::uint32_t>(upgrade)));
    peer.send(request(0x11,source_counter+1,static_cast<std::uint16_t>(*other_end)));stop_at(*other_end);
    const auto& other_cell=topology.cell(*other_end);
    if(visitor_boss && std::count_if(other_cell.neighbors.begin(),other_cell.neighbors.end(),
        [](const auto& next){return next.has_value();})>2) {
        std::uint8_t chosen=0;
        while(chosen<4 && (!other_cell.neighbors[chosen] || chosen==(direction+2U)%4U)) ++chosen;
        check(chosen<4,"summon_other_junction_no_exit");
        peer.send(request(0x34,source_counter+1,chosen));
        check(peer.receive()==Bytes({0x35,0x40,0x34,0x12,chosen}),"summon_other_junction_reply_wrong");
    }
    turn(peer,visitor);
    if(visitor_boss) check(read_le(View(peer.receive()).first(2))==0x4011,"summon_second_boss_move_missing");
    peer.quiet();scenario.stop();
    const auto radius=RichonlineNpcAuraRules::load(resources).radius;
    const auto width=static_cast<std::int32_t>(topology.width());
    const bool in_range=!visitor_boss || (std::abs(endpoint%width-*other_end%width)<=radius &&
        std::abs(endpoint/width-*other_end/width)<=radius);
    const auto amount=summoned && (npc==4 || npc==6) && in_range?800U:0U;
    check(scenario.temple_ledger->snapshot(0).funds.cash==(friendly?before.funds.cash+amount:before.funds.cash-amount) &&
        scenario.temple_ledger->snapshot(1)==boss_before,"summon_tcp_aura_balance_wrong");
    RichonlineActorStatus status;if(summoned)status.possession=npc;
    check(scenario.npcs->actor_begin(visitor,2,status).duplicate,"summon_tcp_duplicate_turn_changed_clock");
    const auto turns=load_richonline_npc_affix(resources,npc);
    if(summoned) for(unsigned next=1;next<turns;++next)
        check(scenario.npcs->actor_begin(visitor,2+next,status).expired.has_value()==(next+1==turns),
            "summon_tcp_wrong_affix_or_duplicate_upgrade_reattached");
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_path_required"); const Network network; const std::filesystem::path resources(argv[1]);
        normal_cards_complete_over_tcp(resources);roadblock_early_stop_over_tcp(resources);
        for (const unsigned level : {0U,1U,5U}) boss_owned_property_completes_over_tcp(resources,level);
        for (const bool upgrade : {false,true})
            for (const auto decision : {Decision::accept,Decision::cancel,Decision::timeout})
                human_owned_property_waits_and_retires_replay(resources,upgrade,decision);
        for(const bool friendly : {false,true}) for(const bool visitor_boss : {false,true})
            for(const std::int8_t npc : {std::int8_t{-1},std::int8_t{0},std::int8_t{1},std::int8_t{3}}) {
            opponent_prebuilt_temple_completes_over_tcp(resources,"BS_1_3.emp",0,164,visitor_boss,npc,friendly);
            opponent_prebuilt_temple_completes_over_tcp(resources,"V_BS_1_1.emp",2,165,visitor_boss,npc,friendly);
        }
        for(const int upgrade : {0,1}) for(const std::int8_t npc : {std::int8_t{1},std::int8_t{3}})
            opponent_prebuilt_temple_completes_over_tcp(resources,"BS_1_3.emp",0,164,false,npc,true,upgrade);
        opponent_prebuilt_temple_completes_over_tcp(resources,"BS_1_3.emp",0,164,true,1,true,1);
        for(const bool boss:{false,true}) for(const bool friendly:{false,true}) {
            for(const unsigned level:{5U,6U,7U}) {
                temple_summon_and_aura_over_tcp(resources,"BS_1_3.emp",0,164,boss,friendly,level,-1);
                temple_summon_and_aura_over_tcp(resources,"V_BS_1_1.emp",2,165,boss,friendly,level,-1);
            }
        }
        for(const int upgrade:{0,1}) for(const unsigned level:{4U,5U,6U})
            temple_summon_and_aura_over_tcp(resources,"BS_1_3.emp",0,164,false,true,level,upgrade);
        temple_summon_and_aura_over_tcp(resources,"V_BS_1_1.emp",2,166,true,true,5,1);
        for(const bool boss:{false,true}) for(const bool friendly:{false,true}) {
            const auto npc=static_cast<std::int8_t>(friendly?3:1);
            opponent_prebuilt_temple_completes_over_tcp(resources,"BS_1_3.emp",0,164,boss,npc,friendly,-1,7);
            opponent_prebuilt_temple_completes_over_tcp(resources,"V_BS_1_1.emp",2,165,boss,npc,friendly,-1,7);
        }
        std::cout<<"PASS encrypted TCP owned property216 BOSS build/upgrade/cap and human wait/accept/cancel/timeout/replay\n";
    } catch (const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
