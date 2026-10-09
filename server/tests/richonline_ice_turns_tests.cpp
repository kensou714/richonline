#include "richonline_boss_cards.hpp"
#include "richonline_boss_landing.hpp"
#include "richonline_game_bank.hpp"
#include "richonline_research_cards.hpp"
#include "richonline_npc_session.hpp"
#include "richonline_boss_property.hpp"
#include "richonline_boss_stage.hpp"
#include "richonline_combat_bridge.hpp"
#include "original_map.hpp"
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
void check(bool value,const char* reason) {if(!value) throw std::runtime_error(reason);}
template<class F> void rejects(F fn) {
    try {fn();} catch(const CodecError&) {return;}
    throw std::runtime_error("expected_ice_rejection");
}
void put(Bytes& bytes,std::size_t offset,std::uint32_t value) {
    for(std::size_t i=0;i<4;++i) bytes.at(offset+i)=static_cast<std::uint8_t>(value>>(8*i));
}
RichonlineRoadTopology geometry(std::int8_t kind=-1) {
    OriginalEmp emp{3,10,1,{},{},Bytes(688,0xff),8,648,0,0};
    for(std::size_t i=0;i<10;++i) if(i<=4 || i>=8) {
        emp.payload.at(emp.terrain_offset+64*i)=8;put(emp.payload,emp.tile_types_offset+4*i,0xffffffffU);
    }
    put(emp.payload,emp.tile_types_offset+4,static_cast<std::uint32_t>(kind));
    return richonline_road_topology(emp);
}
Bytes request(std::uint16_t opcode,std::uint16_t calendar,std::uint32_t argument,std::size_t width=2) {
    Bytes bytes;append_le(bytes,opcode,2);append_le(bytes,calendar,2);append_le(bytes,argument,width);return bytes;
}
Bytes ice(std::uint16_t calendar,std::uint16_t position,std::uint8_t slot=0,std::uint8_t bank=0) {
    auto bytes=request(155,calendar,slot,1);bytes.push_back(bank);append_le(bytes,position,2);return bytes;
}
Bytes fire(std::uint16_t calendar,std::uint16_t position) {auto bytes=ice(calendar,position,1);bytes[0]=157;return bytes;}
Bytes poison(std::uint16_t calendar) {return {156,0,static_cast<std::uint8_t>(calendar),static_cast<std::uint8_t>(calendar>>8),2,0,1,0xa5};}
std::uint16_t op(const Bytes& bytes) {return static_cast<std::uint16_t>(read_le(View(bytes).first(2)));}
void turn(const std::vector<Bytes>& messages,std::uint8_t actor,bool moving) {
    check(messages.size()==(moving?3U:2U) && op(messages[0])==0x4010 && messages[0][4]==actor &&
        op(messages[1])==0x420f && (!moving || op(messages[2])==0x4011),"ice_turn_packets_wrong");
}
struct Room {
    std::shared_ptr<RichonlineBossCards> cards;
    std::shared_ptr<RichonlineGroundObjects> ground=std::make_shared<RichonlineGroundObjects>(
        std::vector<std::int16_t>{0,1,2,3,4,8,9});
    std::shared_ptr<RichonlineGameLedger> ledger=std::make_shared<RichonlineGameLedger>(
        std::vector<RichonlineGameFunds>{{20000,0,150,{}},{100000,0,0,{}}});
    std::atomic<std::int64_t> elapsed{0};
    std::size_t die=0;
    bool reject_landing=false;
    std::vector<RichonlineLandingContext> landed;
    unsigned chance_calls=0;
    std::vector<std::uint8_t> bankrupt;
    RichonlineStartupPlan plan;
    GameAdmission admission{0,3,25,{1,2,3,4,5,6,7,8},19,{}};
    Room(const std::filesystem::path& root,std::int8_t kind=-1,bool enabled=true,bool with_npcs=false,bool with_fire=false,bool with_poison=false) {
        auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
        cards=std::make_shared<RichonlineBossCards>(resources,0x1234,
            RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}});
        RichonlineChanceInventory hand{};hand[0]={1181,3};hand[1]={1183,1};cards->commit_inventory(hand);
        RichonlineBossStartup startup{{3,25,{},{{1,25,0,true}}},
            {0x1234,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
                {{25,0,3,{7,7,7,7,7,7,7,7,7,7},0xb1},{-1,9,1,{},0xc1}}},
            {0x1234,0x4567,1,{{20000,0,150},{100000,0,0}}},{7,-2}};
        startup.room.description.record[36]=3;
        if(with_poison) {
            startup.init.participants[0].position=2;startup.init.participants[1].position=4;
            hand[2]={1182,8};cards->commit_inventory(hand);
        }
        auto balances=std::make_shared<RichonlineBossLandingState>(0x1234,ledger);
        RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
            [this](std::size_t n){return die%n;},[this,balances](const RichonlineLandingContext& context) {
                landed.push_back(context);return balances->land(context);
            },[](View)->RichonlineLandingResult{throw CodecError("unexpected_ice_event");}};
        rules.cards=cards;rules.ground=ground;rules.ledger=ledger;
        rules.now=[this]{return std::chrono::steady_clock::time_point{}+std::chrono::milliseconds{elapsed.load()};};
        rules.ground_card_visible=[](std::uint8_t,std::int16_t,std::int16_t position){return position<9;};
        rules.npc_landing_preflight=[this,balances](const RichonlineLandingContext& context) {
            if(reject_landing) throw CodecError("injected_ice_continuation_rejection");
            balances->validate_landing(context);
        };
        rules.chance_landing=[this](const RichonlineLandingContext&)->std::optional<RichonlineLandingResult> {
            ++chance_calls;return {};
        };
        if(kind==9) rules.bank=std::make_shared<RichonlineGameBank>(0x1234,
            RichonlineGameBankWirePolicy{0xa5,{0xb6,0xc7}},rules.now);
        if(enabled) rules.ice_traps=std::make_shared<const RichonlineResearchTrapRules>(RichonlineResearchTrapRules::load(root));
        if(with_npcs) {
            RichonlineNpcSessionPolicy policy{{0,0,0,3,100,{0,1,3},0xa7,0xa8,0xc7,0xc8,false},17,{1038,1039},{10,20},
                {load_richonline_npc_affix(root,0),load_richonline_npc_affix(root,1)},"ice-fixture-transfer",
                [](std::uint8_t,std::int8_t,const auto&){return std::int16_t{0};}};
            rules.npcs=std::make_shared<RichonlineNpcSession>(0x1234,"BS_1_1.emp",RichonlineNpcRules::load(root),
                resources,std::make_shared<const RichonlineChanceEventTable>(RichonlineChanceEventTable::load(root)),
                ledger,cards,ground,policy);
        }
        if(with_fire || with_poison) {
            const auto stage=load_richonline_boss_stage(root,"BS_1_1.emp");
            auto property=std::make_shared<RichonlineBossProperty>(root,0x1234,ledger,stage);
            RichonlineCombatWorld world;
            world.width=static_cast<std::uint16_t>(stage.width);world.height=static_cast<std::uint16_t>(stage.height);
            world.resources={3000,4000,5000,1000,1500,3,2,1,2,2};
            world.step=[map=geometry(kind)](std::int16_t position,std::uint8_t direction){return map.cell(position).neighbors.at(direction);};
            world.targets=[](std::uint8_t,RichonlineCombatEffect,const RichonlineCombatSessionView&){return std::vector<std::int16_t>{};};
            world.building=[property](const auto& before,auto effect){return property->combat_building_effect(before,effect);};
            world.resolve_terms=[](const auto&,const auto&){return RichonlineCombatWorld::ResolvedTerms{{},{},0,0};};
            rules.combat=std::make_shared<RichonlineCombatBridge>(0x1234,ledger,cards,ground,property,world,RichonlineBossCombatPolicy{});
            rules.combat_random=[]{return RichonlineBossAttackRandomness{{0,0,0,0},[](std::size_t){return std::size_t{0};}};};
            rules.combat_capabilities=[](std::uint8_t,const RichonlineActorStatus&){return RichonlineCombatCapabilities{true,false,false,false,true};};
            rules.terminal=[this,with_poison](const RichonlineTurnTerminalContext& context){
                check(context.reason==(with_poison?RichonlineTerminalReason::poison_card:RichonlineTerminalReason::fire_trap),"research_wrong_terminal_reason");
                bankrupt=context.bankrupt_actors;
                return RichonlineTurnTerminalResult{{request(0x409c,0x1234,bankrupt.at(0))},true};
            };
            rules.fire_traps=std::make_shared<const RichonlineFireTrapRules>(RichonlineFireTrapRules::load(root));
            if(with_poison) {
                rules.poison=std::make_shared<const RichonlinePoisonRules>(RichonlinePoisonRules::load(root));
                rules.poison_raw_actor=[](std::uint8_t){return RichonlineRawActorState{-1,-1,-1,-1,true};};
            }
        }
        plan=make_richonline_boss_turns(startup,geometry(kind),std::move(rules));
    }
    GameCallbacks callbacks() {
        return make_richonline_game_callbacks([this](const GameAdmission& value)->std::optional<RichonlineStartupPlan> {
            return value==admission ? std::optional{plan}:std::nullopt;
        },[](std::size_t size){return Bytes(size,0x91);});
    }
    std::vector<Bytes> action(const Bytes& bytes) {return plan.action({},bytes);}
};
struct Flow {
    Room room;
    GameSession session;
    explicit Flow(const std::filesystem::path& root,std::int8_t kind=-1,bool enabled=true,bool with_fire=false,bool with_poison=false)
        :room(root,kind,enabled,false,with_fire,with_poison),session(ClientVersion::richonline,room.callbacks()) {
        const auto joined=decode(session.feed(encode_frame(encode_game_admission(room.admission,ClientVersion::richonline),
            {Channel::game_c2s,{},ClientVersion::richonline})));
        check(joined.size()==1 && op(joined[0])==0x4000,"ice_admission_failed");
        const auto ready=send({0,0});check(ready.size()==4 && op(ready.back())==0x4011,"ice_ready_failed");
    }
    static std::vector<Bytes> decode(const std::vector<Bytes>& frames) {
        std::vector<Bytes> result;
        for(const auto& bytes:frames) {
            const auto frame=decode_frame(bytes,{Channel::game_s2c,{},ClientVersion::richonline});
            if(frame.wire_type!=1) result.push_back(decode_inner(decode_envelope(frame,ClientVersion::richonline).encoded));
        }
        return result;
    }
    std::vector<Bytes> send(const Bytes& bytes) {
        auto result=decode(session.feed(encode_frame(richonline_board_frame(bytes,{7,-2},Bytes(bytes.size()+2,0x91)),
            {Channel::game_c2s,{},ClientVersion::richonline})));
        check(session.state()==GameState::admitted,"ice_session_disconnected");return result;
    }
    void human() {send(request(0x11,0x4568,8));}
    std::vector<Bytes> poll() {return decode(session.poll());}
};
void placement_and_refusal(const std::filesystem::path& root) {
    Flow flow(root);flow.human();
    const auto placed=flow.send(ice(0x4569,1));
    check(placed==std::vector<Bytes>{{0xeb,0x40,0x34,0x12,0,0,1,0}},"ice_success_wire_or_extra_ack");
    check(flow.room.cards->inventory()[0].count==2 && flow.room.ground->snapshot().objects.at(1)==RichonlineGroundObject{25,255,255},"ice_authority_missing");
    for(const auto& invalid:std::vector<Bytes>{ice(0x4569,1),ice(0x4569,0),ice(0x4569,8),ice(0x4569,9),
        ice(0x4569,5),ice(0x4569,2,1),ice(0x4569,2,0,1),ice(0x4569,0xffff),
        {156,0,0x69,0x45,0,0,1,0xa5},{157,0,0x69,0x45,1,0,2,0}}) {
        const auto hand=flow.room.cards->inventory();const auto ground=flow.room.ground->snapshot();
        const auto refused=flow.send(invalid);
        check(refused.size()==1 && op(refused[0])==0x400b && flow.room.cards->inventory()==hand &&
            flow.room.ground->snapshot()==ground,"ice_refusal_mutated_or_disconnected");
    }
    flow.send(ice(0x4569,2));check(flow.room.cards->inventory()[0].count==1,"ice_refusal_lost_roll_phase");
    const auto ground=flow.room.ground->snapshot();
    rejects([&]{flow.room.action(ice(0x4568,3));});
    check(flow.room.ground->snapshot()==ground,"ice_old_calendar_mutated");
    flow.send(request(0x10,0x4569,0,4));
    rejects([&]{flow.room.action(ice(0x4569,3));});
    Flow disabled(root,-1,false);disabled.human();
    check(op(disabled.send(ice(0x4569,1))[0])==0x400b,"ice_missing_capability_not_refused");
}
void human_freezes_and_recovers(const std::filesystem::path& root,std::int8_t kind) {
    Flow flow(root,kind);flow.human();flow.send(ice(0x4569,1));
    const auto cash=flow.room.ledger->snapshot(0);const auto chance=flow.room.chance_calls;
    flow.send(request(0x10,0x4569,0,4));
    const auto stopped=flow.send(request(0x11,0x4569,1));
    check(stopped.size()==4 && op(stopped[0])==0x4013 && op(stopped[1])==0x4010,
        "ice_landing_extra_packet_or_missing_continuation");
    check(flow.room.ground->snapshot().objects.empty() && flow.room.landed.back().actor_status.frozen==3 &&
        flow.room.chance_calls==chance && flow.room.ledger->snapshot(0).funds==cash.funds,"ice_static_effect_not_suppressed");
    for(std::uint16_t skip=0;skip<2;++skip) {
        const auto frozen=flow.send(request(0x11,static_cast<std::uint16_t>(0x456a+2*skip),skip==0?9U:8U));
        check(frozen.size()==3 && op(frozen[0])==0x4013,"ice_boss_stop_wrong");
        turn({frozen.begin()+1,frozen.end()},0,false);
        flow.room.elapsed.fetch_add(1799);check(flow.poll().empty(),"ice_timer_advanced_early");
        flow.room.elapsed.fetch_add(1);turn(flow.poll(),1,true);
        check(flow.poll().empty(),"ice_timer_advanced_twice");
    }
    const auto unfrozen=flow.send(request(0x11,0x456e,9));
    turn({unfrozen.begin()+1,unfrozen.end()},0,false);
    flow.send(request(0x10,0x456f,0,4));flow.send(request(0x11,0x456f,2));
    check(flow.room.landed.back().actor_status.frozen==0,"ice_failed_to_expire_after_two_skips");
}
void boss_freezes_and_pass_through_does_not(const std::filesystem::path& root) {
    Flow flow(root);flow.room.ground->place(8,{25,255,255});flow.human();
    check(flow.room.landed.back().actor_slot==1 && flow.room.landed.back().actor_status.frozen==3 &&
        flow.room.ground->snapshot().objects.empty(),"mode3_boss_ice_bypassed");
    for(std::uint16_t skip=0;skip<2;++skip) {
        const auto cal=static_cast<std::uint16_t>(0x4569+2*skip);
        flow.send(request(0x10,cal,0,4));
        const auto stopped=flow.send(request(0x11,cal,skip+1U));
        turn({stopped.begin()+1,stopped.end()},1,false);
        flow.room.elapsed.fetch_add(1800);turn(flow.poll(),0,false);
    }
    flow.send(request(0x10,0x456d,0,4));const auto done=flow.send(request(0x11,0x456d,3));
    turn({done.begin()+1,done.end()},1,true);
    Flow passing(root);passing.human();passing.send(ice(0x4569,1));passing.room.die=1;
    passing.send(request(0x10,0x4569,0,4));passing.send(request(0x11,0x4569,2));
    check(passing.room.ground->snapshot().objects.contains(1) && passing.room.landed.back().actor_status.frozen==0,
        "ice_triggered_mid_route");
}
void preflight_failure_is_atomic(const std::filesystem::path& root) {
    Room room(root);room.plan.map_ready();room.action(request(0x11,0x4568,8));room.action(ice(0x4569,1));
    room.action(request(0x10,0x4569,0,4));const auto ground=room.ground->snapshot();const auto hand=room.cards->inventory();
    room.reject_landing=true;rejects([&]{room.action(request(0x11,0x4569,1));});
    check(room.ground->snapshot()==ground && room.cards->inventory()==hand,"ice_partial_commit_on_preflight_failure");
    room.reject_landing=false;room.action(request(0x11,0x4569,1));
    check(room.landed.back().actor_status.frozen==3 && room.ground->snapshot().objects.empty(),"ice_retry_not_possible");
}
void possession_clock_survives_ice(const std::filesystem::path& root) {
    Room room(root,-1,true,true);room.plan.map_ready();room.ground->place(8,{3,255,255});
    room.action(request(0x11,0x4568,8));check(room.landed.back().actor_status.possession==3,"ice_fixture_npc_not_attached");
    room.ground->place(9,{25,255,255});room.action(request(0x10,0x4569,0,4));room.action(request(0x11,0x4569,1));
    room.action(request(0x11,0x456a,9));
    check(room.landed.back().actor_status.possession==3 && room.landed.back().actor_status.frozen==3,"ice_detached_possession");
    for(std::uint16_t skip=0;skip<2;++skip) {
        const auto cal=static_cast<std::uint16_t>(0x456b+2*skip);
        room.action(request(0x10,cal,0,4));auto result=room.action(request(0x11,cal,2U+skip));
        turn({result.begin()+1,result.end()},1,false);room.elapsed.fetch_add(1800);turn(room.plan.poll(),0,false);
    }
    room.action(request(0x10,0x456f,0,4));room.action(request(0x11,0x456f,4));room.action(request(0x11,0x4570,8));
    check(room.landed.back().actor_status.frozen==0 && room.landed.back().actor_status.possession==3,
        "ice_wrong_possession_duration_at_own_turn5");
    room.action(request(0x10,0x4571,0,4));room.action(request(0x11,0x4571,3));room.action(request(0x11,0x4572,9));
    check(!room.landed.back().actor_status.possession,"ice_extended_possession_clock");
}
void property_continuation(const std::filesystem::path& root) {
    const auto topology=load_richonline_road_topology(root/"Map/BS_1_1.emp");
    for(const bool owned:{false,true}) {
        auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
        auto cards=std::make_shared<RichonlineBossCards>(resources,0x1234,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0,0}});
        RichonlineChanceInventory hand{};hand[0]={1181,1};cards->commit_inventory(hand);
        auto property=std::make_shared<RichonlineBossProperty>(root,0x1234,std::array<std::uint32_t,2>{20000,100000},
            load_richonline_boss_stage(root,"BS_1_1.emp"));
        property->enable_human_decisions(std::chrono::seconds{5},[]{return std::chrono::steady_clock::time_point{};});
        if(owned) property->land({1,232,33,216,3,true,2,false});
        const auto cash=property->cash();const auto owner=property->owner(216);
        auto ground=std::make_shared<RichonlineGroundObjects>(std::vector<std::int16_t>{232});
        RichonlineBossStartup startup{{3,25,{},{{1,25,0,true}}},
            {0x1234,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
                {{25,233,1,{7,7,7,7,7,7,7,7,7,7},0xb1},{-1,236,1,{},0xc1}}},
            {0x1234,0x4567,1,{{20000,0,150},{100000,0,0}}},{7,-2}};
        startup.room.description.record[36]=3;bool frozen_property=false;
        RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
            [](std::size_t){return std::size_t{0};},[&](const RichonlineLandingContext& context) {
                if(auto result=property->land(context)) {frozen_property=context.actor_status.frozen==3;return *result;}
                return resolve_richonline_empty_boss_landing(0x1234,context);
            },[](View)->RichonlineLandingResult{throw CodecError("ice_property_unexpected_decision");}};
        rules.cards=cards;rules.ground=ground;
        rules.ice_traps=std::make_shared<const RichonlineResearchTrapRules>(RichonlineResearchTrapRules::load(root));
        rules.ground_card_visible=[](std::uint8_t,std::int16_t,std::int16_t){return true;};
        rules.npc_landing_preflight=[property](const RichonlineLandingContext& context) {
            if(!property->validate_landing(context)) static_cast<void>(resolve_richonline_empty_boss_landing(0x1234,context));
        };
        auto plan=make_richonline_boss_turns(startup,topology,std::move(rules));plan.map_ready();
        plan.action({},request(0x11,0x4568,235));plan.action({},ice(0x4569,232));
        plan.action({},request(0x10,0x4569,0,4));const auto result=plan.action({},request(0x11,0x4569,232));
        check(frozen_property && result.size()==4 && op(result[0])==0x4013 && op(result[1])==0x4010 &&
            property->cash()==cash && property->owner(216)==owner && !property->poll() && ground->snapshot().objects.empty(),
            "ice_property_continuation_skipped_or_invented_purchase");
    }
}
void fire_lifecycle(const std::filesystem::path& root) {
    Flow flow(root,-1,true,true);flow.human();
    check(flow.send(fire(0x4569,1))==std::vector<Bytes>{{0xed,0x40,0x34,0x12,1,0,1,0}},"fire_placement_wire");
    check(flow.room.ground->snapshot().objects==RichonlineGroundMap{{1,{26,0,3}},{2,{26,0,3}}} &&
        flow.room.cards->inventory()[1].count==0,"fire_area_owner_or_inventory");
    check(op(flow.send(fire(0x4569,1))[0])==0x400b,"fire_unowned_replay_not_refused");
    flow.send(request(0x10,0x4569,0,4));auto stop=flow.send(request(0x11,0x4569,1));
    check(op(stop[0])==0x4013 && std::count_if(stop.begin(),stop.end(),[](const auto& packet){return op(packet)==0x4013;})==1 &&
        flow.room.ledger->snapshot(0).funds.cash==18000 && flow.room.ground->snapshot().objects.at(1).byte8==3,
        "fire_hit_removes_trap_or_wrong_damage");
    flow.send(request(0x11,0x456a,9));check(flow.room.ground->snapshot().objects.at(1).byte8==2,"fire_owner_clock_not_ticked");
    flow.send(request(0x10,0x456b,0,4));flow.send(request(0x11,0x456b,2));
    check(flow.room.ledger->snapshot(0).funds.cash==16000,"fire_second_tile_not_damaging");
    flow.send(request(0x11,0x456c,8));check(flow.room.ground->snapshot().objects.at(1).byte8==1,"fire_second_owner_clock");
    flow.send(request(0x10,0x456d,0,4));flow.send(request(0x11,0x456d,3));flow.send(request(0x11,0x456e,9));
    check(flow.room.ground->snapshot().objects.empty(),"fire_expiry_not_removed");
    check(flow.poll().empty(),"fire_clock_emitted_extra_packet");
    Flow boss(root,-1,true,true);boss.room.ground->place(8,{26,0,3});boss.human();
    check(boss.room.ledger->snapshot(1).funds.cash==98000 && boss.room.ground->snapshot().objects.at(8).byte8==2,
        "fire_mode3_boss_damage_or_clock");
    Flow passing(root,-1,true,true);passing.human();passing.send(fire(0x4569,1));passing.room.die=2;
    passing.send(request(0x10,0x4569,0,4));passing.send(request(0x11,0x4569,3));
    check(passing.room.ledger->snapshot(0).funds.cash==20000,"fire_midroute_damage");
    Flow empty(root,-1,true,true);empty.human();empty.room.ground->place(1,{25,255,255});
    check(op(empty.send(fire(0x4569,0))[0])==0x40ed && empty.room.cards->inventory()[1].count==0 &&
        empty.room.ground->snapshot().objects==RichonlineGroundMap{{1,{25,255,255}}},"fire_empty_footprint_must_consume");
    for(const auto amount:{2000U,2001U}) {
        Room lethal(root,68,true,false,true);lethal.plan.map_ready();lethal.action(request(0x11,0x4568,8));
        const auto before=lethal.ledger->snapshot(0);auto funds=before.funds;funds.cash=500;funds.deposit=amount-500;
        lethal.ledger->commit(0,before,funds);lethal.action(fire(0x4569,1));lethal.action(request(0x10,0x4569,0,4));
        const auto ground=lethal.ground->snapshot();
        if(amount==2000) {
            const auto result=lethal.action(request(0x11,0x4569,1));
            check(result.size()==2 && op(result[0])==0x4013 && op(result[1])==0x409c &&
                lethal.bankrupt==std::vector<std::uint8_t>{0} && lethal.ground->snapshot()==ground,
                "fire_terminal_continued_to_unsupported_static");
        } else {
            const auto cash=lethal.ledger->snapshot(0);
            rejects([&]{lethal.action(request(0x11,0x4569,1));});
            check(lethal.ledger->snapshot(0)==cash && lethal.ground->snapshot()==ground && lethal.bankrupt.empty(),
                "fire_survivor_preflight_partial_commit");
        }
    }
}
void poison_lifecycle(const std::filesystem::path& root) {
    Flow f(root,-1,true,false,true);f.send(request(0x11,0x4568,3));
    for(unsigned use=0;use<4;++use) {
        const auto cash=f.room.ledger->snapshot(1).funds.cash;
        check(f.send(poison(0x4569))==std::vector<Bytes>{{0xec,0x40,0x34,0x12,2,0,1,0xa5}},"poison_wire_or_extra_ack");
        check(f.room.ledger->snapshot(1).funds.cash==cash-(use==3?3750U:2500U),"poison_same_action_strength");
        if(use==1) {
            auto bad=poison(0x4569);bad[5]=1;
            check(op(f.send(bad)[0])==0x400b,"poison_invalid_bank_not_refused");
        }
    }
    f.send(request(0x10,0x4569,0,4));f.send(request(0x11,0x4569,3));f.send(request(0x11,0x456a,2));
    const auto cash=f.room.ledger->snapshot(1).funds.cash;f.send(poison(0x456b));
    check(f.room.ledger->snapshot(1).funds.cash==cash-2500 && f.room.cards->inventory()[2].count==3,"poison_counter_not_reset_on_turn");
    const auto before=f.room.ledger->snapshot(1);rejects([&]{f.room.action(poison(0x4569));});
    check(f.room.ledger->snapshot(1)==before,"poison_old_calendar_mutated");
    auto funds=before.funds;funds.cash=500;funds.deposit=2000;f.room.ledger->commit(1,before,funds);
    const auto terminal=f.send(poison(0x456b));
    check(terminal.size()==2 && op(terminal[0])==0x40ec && op(terminal[1])==0x409c &&
        f.room.bankrupt==std::vector<std::uint8_t>{1},"poison_terminal_order");
    // A coordinate ray reaches road8 from road4 across nonroads5..7 at range4.
    const auto footprint=richonline_poison_map_footprint(geometry(),4,4);
    check(std::any_of(footprint.begin(),footprint.end(),[](const auto& cell){return cell.position==8 && cell.attenuation_layer==3;}) &&
        std::none_of(footprint.begin(),footprint.end(),[](const auto& cell){return cell.position>=5 && cell.position<=7;}),
        "poison_rays_stopped_at_nonroad");
}
struct Peer {
    SOCKET socket=INVALID_SOCKET;
    explicit Peer(std::uint16_t port) {
        socket=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);check(socket!=INVALID_SOCKET,"ice_tcp_socket");
        const DWORD timeout=3000;
        for(const auto option:{SO_RCVTIMEO,SO_SNDTIMEO})
            check(setsockopt(socket,SOL_SOCKET,option,reinterpret_cast<const char*>(&timeout),sizeof(timeout))==0,"ice_tcp_timeout");
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(port);
        check(inet_pton(AF_INET,"127.0.0.1",&address.sin_addr)==1 &&
            connect(socket,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"ice_tcp_connect");
    }
    ~Peer(){closesocket(socket);}
    void send_frame(const Frame& frame) {
        const auto wire=encode_frame(frame,{Channel::game_c2s,{},ClientVersion::richonline});View left(wire);
        while(!left.empty()) {
            const auto n=::send(socket,reinterpret_cast<const char*>(left.data()),static_cast<int>(left.size()),0);
            check(n>0,"ice_tcp_send");left=left.subspan(static_cast<std::size_t>(n));
        }
    }
    void send(const Bytes& plain){send_frame(richonline_board_frame(plain,{7,-2},Bytes(plain.size()+2,0x91)));}
    Bytes read(std::size_t size) {
        Bytes result(size);
        for(std::size_t offset=0;offset<size;) {
            const auto n=recv(socket,reinterpret_cast<char*>(result.data()+offset),static_cast<int>(size-offset),0);
            check(n>0,"ice_tcp_receive");offset+=static_cast<std::size_t>(n);
        }
        return result;
    }
    Frame frame() {
        auto bytes=read(8);const auto size=read_le(View(bytes).subspan(4,4));
        check(size>=8 && size<=max_frame_total,"ice_tcp_frame_length");
        auto tail=read(size-8);bytes.insert(bytes.end(),tail.begin(),tail.end());
        return decode_frame(bytes,{Channel::game_s2c,{},ClientVersion::richonline});
    }
    Bytes receive(){const auto received=frame();check(received.wire_type==299,"ice_tcp_envelope");
        return decode_inner(decode_envelope(received,ClientVersion::richonline).encoded);}
    void quiet(){fd_set set;FD_ZERO(&set);FD_SET(socket,&set);timeval delay{0,50000};
        check(select(0,&set,nullptr,nullptr,&delay)==0,"ice_tcp_extra_packet");}
};
void encrypted_tcp(const std::filesystem::path& root,bool flames=false,bool toxic=false) {
    Room room(root,(flames||toxic)?std::int8_t{-1}:std::int8_t{9},true,false,flames,toxic);
    std::mutex mutex;std::condition_variable changed;bool listening=false;std::exception_ptr failure;
    GameService service({"127.0.0.1",0,ClientVersion::richonline},[&]{return room.callbacks();},[&](const std::string& line){
        const std::lock_guard lock(mutex);if(line.starts_with("game_transport_listening port=")) listening=true;changed.notify_all();
    });
    std::thread worker([&]{try{service.run();}catch(...){const std::lock_guard lock(mutex);failure=std::current_exception();changed.notify_all();}});
    try {
        {std::unique_lock lock(mutex);check(changed.wait_for(lock,std::chrono::seconds{5},[&]{return listening || failure;}),"ice_tcp_listen");
            if(failure)std::rethrow_exception(failure);}
        Peer peer(service.bound_port());peer.send_frame(encode_game_admission(room.admission,ClientVersion::richonline));
        check(peer.frame().wire_type==1 && op(peer.receive())==0x4000,"ice_tcp_admission");
        peer.send({0,0});check(op(peer.receive())==0x4004,"ice_tcp_snapshot");
        turn({peer.receive(),peer.receive(),peer.receive()},1,true);
        peer.send(request(0x11,0x4568,toxic?3U:8U));check(op(peer.receive())==0x4013,"ice_tcp_boss_stop");
        turn({peer.receive(),peer.receive()},0,false);
        if(toxic) {
            for(unsigned use=0;use<4;++use) {
                peer.send(poison(0x4569));check(peer.receive()==Bytes({0xec,0x40,0x34,0x12,2,0,1,0xa5}),"poison_tcp_success");peer.quiet();
            }
            peer.send(request(0x10,0x4569,0,4));check(op(peer.receive())==0x4011,"poison_tcp_roll");
            peer.send(request(0x11,0x4569,3));check(op(peer.receive())==0x4013,"poison_tcp_stop");
            const auto next=peer.receive();check(op(peer.receive())==0x401e,"poison_tcp_mine_clock");
            turn({next,peer.receive(),peer.receive()},1,true);
            peer.send(request(0x11,0x456a,2));check(op(peer.receive())==0x4013,"poison_tcp_boss_stop");
            turn({peer.receive(),peer.receive()},0,false);
            peer.send(poison(0x456b));check(op(peer.receive())==0x40ec,"poison_tcp_next_turn_use");peer.quiet();
            service.stop();worker.join();
            check(room.ledger->snapshot(1).funds.cash==86250 && room.cards->inventory()[2].count==3,
                "poison_tcp_counter_damage_reset");return;
        }
        if(flames) {
            peer.send(fire(0x4569,1));check(peer.receive()==Bytes({0xed,0x40,0x34,0x12,1,0,1,0}),"fire_tcp_place");peer.quiet();
            peer.send(fire(0x4569,1));check(op(peer.receive())==0x400b,"fire_tcp_replay");peer.quiet();
            for(std::uint16_t step=0;step<3;++step) {
                const auto cal=static_cast<std::uint16_t>(0x4569+2*step);
                peer.send(request(0x10,cal,0,4));check(op(peer.receive())==0x4011,"fire_tcp_roll");
                peer.send(request(0x11,cal,step+1U));check(op(peer.receive())==0x4013,"fire_tcp_stop");
                const auto next=peer.receive();check(op(peer.receive())==0x401e,"fire_tcp_expected_existing_mine_clock");
                turn({next,peer.receive(),peer.receive()},1,true);
                peer.send(request(0x11,static_cast<std::uint16_t>(cal+1),step==1?8U:9U));
                check(op(peer.receive())==0x4013,"fire_tcp_boss_stop");turn({peer.receive(),peer.receive()},0,false);peer.quiet();
            }
            service.stop();worker.join();
            check(room.ledger->snapshot(0).funds.cash==16000 && room.ground->snapshot().objects.empty(),"fire_tcp_damage_expiry");
            return;
        }
        peer.send(ice(0x4569,1));check(peer.receive()==Bytes({0xeb,0x40,0x34,0x12,0,0,1,0}),"ice_tcp_place");peer.quiet();
        peer.send(ice(0x4569,1));check(op(peer.receive())==0x400b,"ice_tcp_duplicate_refusal");peer.quiet();
        peer.send(request(0x10,0x4569,0,4));check(op(peer.receive())==0x4011,"ice_tcp_roll");
        peer.send(request(0x11,0x4569,1));check(op(peer.receive())==0x4013,"ice_tcp_stop");
        turn({peer.receive(),peer.receive(),peer.receive()},1,true);
        for(std::uint16_t skip=0;skip<2;++skip) {
            peer.send(request(0x11,static_cast<std::uint16_t>(0x456a+2*skip),skip==0?9U:8U));
            check(op(peer.receive())==0x4013,"ice_tcp_next_boss_stop");turn({peer.receive(),peer.receive()},0,false);peer.quiet();
            room.elapsed.fetch_add(1800);turn({peer.receive(),peer.receive(),peer.receive()},1,true);peer.quiet();
        }
        peer.send(request(0x11,0x456e,9));check(op(peer.receive())==0x4013,"ice_tcp_final_boss_stop");
        turn({peer.receive(),peer.receive()},0,false);
        peer.send(request(0x10,0x456f,0,4));check(op(peer.receive())==0x4011,"ice_tcp_unfrozen_roll");
        peer.send(request(0x11,0x456f,2));check(op(peer.receive())==0x4013,"ice_tcp_unfrozen_stop");
        turn({peer.receive(),peer.receive(),peer.receive()},1,true);
        service.stop();worker.join();
        check(room.cards->inventory()[0].count==2 && room.ground->snapshot().objects.empty() &&
            room.landed.back().actor_status.frozen==0,"ice_tcp_authority_mismatch");
    } catch(...) {service.stop();if(worker.joinable())worker.join();throw;}
}
}
int main(int argc,char** argv) {
    try {
        if(argc!=2)return 2;const auto root=std::filesystem::path(argv[1]);
        const auto rules=RichonlineResearchTrapRules::load(root);
        check(rules.freeze_timer==3 && rules.fire_radius==1 && rules.fire_rounds==3,"ice_real_gvalue_changed");
        const auto resources=RichonlineChanceResources::load(root);
        for(const auto* map:{"BS_1_1.emp","BS_1_2.emp","BS_1_4.emp"})
            for(const std::int16_t card:std::array<std::int16_t,3>{1181,1182,1183})
                check(resources.automatic_card_eligible(map,card),"research_real_map_membership_missing");
        placement_and_refusal(root);
        for(const std::int8_t kind:std::array<std::int8_t,4>{-1,5,9,68})human_freezes_and_recovers(root,kind);
        boss_freezes_and_pass_through_does_not(root);preflight_failure_is_atomic(root);
        possession_clock_survives_ice(root);property_continuation(root);
        const auto fire_rules=RichonlineFireTrapRules::load(root);check(fire_rules.npc26_damage==2000,"fire_npc26_resource");
        fire_lifecycle(root);
        const auto poison_rules=RichonlinePoisonRules::load(root);
        check(poison_rules.range==3 && poison_rules.base_damage==2500,"poison_real_resources");poison_lifecycle(root);
        WSADATA data{};check(WSAStartup(MAKEWORD(2,2),&data)==0,"ice_winsock_start");
        try{encrypted_tcp(root);encrypted_tcp(root,true);encrypted_tcp(root,false,true);}catch(...){WSACleanup();throw;}WSACleanup();
        std::cout<<"PASS NEW155/156/157 research cards: shared state, turn clocks, damage, refusal and encrypted TCP\n";
    } catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
