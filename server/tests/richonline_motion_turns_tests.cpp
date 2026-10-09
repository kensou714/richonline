#include "richonline_motion_card.hpp"
#include "richonline_game_bank.hpp"
#include "richonline_game_ledger.hpp"
#include "richonline_npc_session.hpp"
#include "richonline_combat_bridge.hpp"
#include "richonline_boss_stage.hpp"
#include "richonline_game_end.hpp"
#include "richonline_raw_authority.hpp"
#include "original_map.hpp"
#include <algorithm>
#include <iostream>

namespace {
using namespace richnet;
constexpr std::uint16_t gid=0x1234,initial_counter=0x4567;
void check(bool ok,const char* why) { if (!ok) throw std::runtime_error(why); }
std::uint16_t opcode(const Bytes& b) { return static_cast<std::uint16_t>(read_le(View(b).first(2))); }
Bytes request(std::uint16_t op,std::uint16_t counter,std::uint32_t value,std::size_t width=2) {
    Bytes result; append_le(result,op,2); append_le(result,counter,2); append_le(result,value,width); return result;
}
std::vector<Bytes> decode(const std::vector<Bytes>& bytes) {
    std::vector<Bytes> result;
    for (const auto& b:bytes) {
        const auto frame=decode_frame(b,{Channel::game_s2c,{},ClientVersion::richonline});
        if(frame.wire_type!=1) result.push_back(decode_inner(decode_envelope(frame,ClientVersion::richonline).encoded));
    }
    return result;
}
RichonlineRoadTopology geometry(bool bank_junction=false,bool blocked_route=false) {
    const std::size_t area=bank_junction ? 60 : 30;
    OriginalEmp emp{3,30,bank_junction ? 2U : 1U,{}, {},Bytes(8+68*area,0xff),8,8+64*area,0,0};
    for (std::size_t pos=0;pos<30;++pos) if(pos<=12 || pos>=20)
        emp.payload[emp.terrain_offset+64*pos]=8;
    if(bank_junction) {
        emp.payload[emp.terrain_offset+64*33]=8;
        emp.payload[emp.tile_types_offset+4*3]=9;
    }
    if(blocked_route) emp.payload[emp.tile_types_offset+4*6]=67;
    return richonline_road_topology(emp);
}
struct Flow {
    std::shared_ptr<RichonlineBossCards> cards;
    std::vector<RichonlineLandingContext> landed;
    std::vector<std::string> logs;
    std::unique_ptr<GameSession> session;
    const GameAdmission admission{0,3,25,{1,2,3,4,5,6,7,8},19,{}};
    std::uint16_t counter=initial_counter;
    std::optional<Bytes> last_move;
    std::function<std::vector<Bytes>(const Envelope299&,View)> raw_action;
    std::shared_ptr<RichonlineGroundObjects> ground;
    std::shared_ptr<RichonlineGameLedger> ledger;
    std::chrono::steady_clock::time_point now{};
    std::vector<std::int16_t> visible_npcs;
    bool reject_collision=false;
    std::array<std::uint8_t,4> combat_rolls{};
    std::vector<RichonlineTurnTerminalContext> terminal_calls;
    std::function<std::optional<RichonlineLandingStatusChange>(const RichonlineLandingContext&)> status_transition;
    std::optional<std::size_t> controlled_fork_choice;
    std::shared_ptr<RichonlineRawAuthority> raw_authority;
    Flow(const std::filesystem::path& root,bool bank_junction=false,std::uint8_t boss_dice=1,
        bool blocked_route=false,bool npc_enabled=false,bool event_wait=false,
        std::int16_t human_position=3,std::uint8_t human_heading=3,bool combat_enabled=false,bool npc_sleep=false,
        bool timed_bombs=false,std::uint16_t initial_calendar=initial_counter) {
        counter=initial_calendar;
        cards=std::make_shared<RichonlineBossCards>(
            std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root)),gid,
            RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}});
        RichonlineBossStartup startup{{3,25,{},{{1,25,0,true}}},
            {gid,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
                {{25,human_position,human_heading,{7,7,7,7,7,7,7,7,7,7},0xb1},{-1,27,1,{},0xc1}}},
            {gid,initial_calendar,1,{{1000,0,150},{5000,0,0}}},{7,-2}};
        startup.room.description.record[36]=3;
        RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
            [this](std::size_t n){
                if(n==1)return std::size_t{0};
                if(n==2 && controlled_fork_choice)return *controlled_fork_choice;
                check(n==6,"unexpected_motion_fork");return std::size_t{3};
            },
            [this,event_wait](const RichonlineLandingContext& ctx) {
                landed.push_back(ctx);
                auto stop=request(0x4013,gid,static_cast<std::uint16_t>(ctx.position));
                return RichonlineLandingResult{{std::move(stop)},
                    event_wait && ctx.actor_slot==0 ? RichonlineLandingProgress::await_event : RichonlineLandingProgress::complete,
                    event_wait && ctx.actor_slot==0 ? std::optional<std::uint16_t>{0x20} : std::nullopt,
                    status_transition ? status_transition(ctx) : std::nullopt};
            },[event_wait](View bytes)->RichonlineLandingResult {
                if(event_wait && bytes.size()==6 && read_le(bytes.first(2))==0x20)
                    return {{},RichonlineLandingProgress::complete};
                throw CodecError("unexpected_motion_event");}};
        rules.cards=cards; rules.motion_cards=std::make_shared<RichonlineMotionCardRules>(RichonlineMotionCardRules::load(root));
        rules.boss_dice_count=boss_dice;
        rules.now=[this]{return now;};
        rules.log=[this](const std::string& line){logs.push_back(line);};
        if(bank_junction || npc_enabled) {
            rules.ledger=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{
                {1000,200,150,{}},{5000,400,0,{}}});
            ledger=rules.ledger;
            if(bank_junction) rules.bank=std::make_shared<RichonlineGameBank>(gid,RichonlineGameBankWirePolicy{0xa5,{0xb6,0xc7}},
                []{return RichonlineGameBank::Clock::time_point{};});
        }
        if(npc_enabled) {
            rules.npc_landing_preflight=[this](const RichonlineLandingContext& context) {
                if(context.occupied_by_other_actor && (reject_collision || !context.collision_resolved))
                    throw CodecError("test_npc_collision_unimplemented");
            };
            rules.npc_summon_candidates=[this](const RichonlineLandingContext&){return visible_npcs;};
            std::vector<std::int16_t> positions;
            for(std::int16_t pos=0;pos<30;++pos) if(pos<=12 || pos>=20) positions.push_back(pos);
            ground=std::make_shared<RichonlineGroundObjects>(std::move(positions));
            auto npc_policy=RichonlineNpcSessionPolicy{
                {0,0,0,5,3,{0,1,3},0x91,0x92,0x93,0x94,false},19,{1038,1044},{25,-1},
                {load_richonline_npc_affix(root,0),load_richonline_npc_affix(root,1)},
                "test-fixed-20",[](std::uint8_t,std::int8_t,const auto&){return std::int16_t{20};}};
            if(timed_bombs) npc_policy.spawn.refresh_every_rounds=1000;
            if(npc_sleep) npc_policy.sleep_deity=RichonlineNpcSleepPolicy{load_richonline_npc_affix(root,7),
                "test-no-active-protection",[](std::uint8_t,const auto&,const auto&) {
                    return RichonlineSleepProtection{false,{}};
                }};
            rules.npcs=std::make_shared<RichonlineNpcSession>(gid,"BS_1_1.emp",RichonlineNpcRules::load(root),
                std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root)),
                std::make_shared<const RichonlineChanceEventTable>(RichonlineChanceEventTable::load(root)),
                ledger,cards,ground,std::move(npc_policy));
        }
        if(combat_enabled) {
            check(npc_enabled,"combat_fixture_requires_shared_npc_stores");
            const auto stage=load_richonline_boss_stage(root,"BS_1_1.emp");
            auto property=std::make_shared<RichonlineBossProperty>(root,gid,ledger,stage);
            const auto actual_topology=load_richonline_road_topology(root/"Map"/"BS_1_1.emp");
            RichonlineCombatWorld world;
            world.width=static_cast<std::uint16_t>(actual_topology.width());
            world.height=static_cast<std::uint16_t>(actual_topology.height());
            world.resources={50,100,200,100,200,3,1,1,1,1};
            world.step=[width=world.width,height=world.height](std::int16_t position,std::uint8_t direction)
                ->std::optional<std::int16_t> {
                const auto x=position%width,y=position/width;
                if(direction==0 && x>0)return static_cast<std::int16_t>(position-1);
                if(direction==1 && x+1<width)return static_cast<std::int16_t>(position+1);
                if(direction==2 && y>0)return static_cast<std::int16_t>(position-width);
                if(direction==3 && y+1<height)return static_cast<std::int16_t>(position+width);
                return {};
            };
            world.targets=[](std::uint8_t,RichonlineCombatEffect,const RichonlineCombatSessionView& state) {
                return std::vector<std::int16_t>{state.actors[0]->position};
            };
            world.card_targets=[this](std::uint8_t,RichonlineCombatEffect,const RichonlineCombatSessionView& state) {
                auto positions=ground->positions();
                for(const auto& actor:state.actors) if(actor &&
                    std::find(positions.begin(),positions.end(),actor->position)==positions.end())
                    positions.push_back(actor->position);
                return positions;
            };
            world.resolve_terms=[](const RichonlineCombatActorView&,const RichonlineCombatSessionView&) {
                return RichonlineCombatWorld::ResolvedTerms{{},{},0,0};
            };
            world.building=[property](const RichonlineCombatBuildingView& before,RichonlineBossBlastBuildingEffect effect) {
                return property->combat_building_effect(before,effect);
            };
            rules.combat=std::make_shared<RichonlineCombatBridge>(gid,ledger,cards,ground,property,std::move(world),
                RichonlineBossCombatPolicy{});
            rules.combat_random=[this] {
                return RichonlineBossAttackRandomness{combat_rolls,[](std::size_t){return std::size_t{0};}};
            };
            rules.combat_capabilities=[](std::uint8_t,const RichonlineActorStatus&) {
                return RichonlineCombatCapabilities{true,false,false,false,true};
            };
            rules.terminal=[this](const RichonlineTurnTerminalContext& ctx) {
                terminal_calls.push_back(ctx);
                return RichonlineTurnTerminalResult{{richonline_bankruptcy_notice(gid,
                    static_cast<std::int8_t>(ctx.bankrupt_actors.front()))},true};
            };
        }
        if(timed_bombs) {
            check(combat_enabled,"timed_bomb_fixture_requires_shared_combat");
            rules.timed_bombs=std::make_shared<const RichonlineTimedBombTurnPolicy>(RichonlineTimedBombTurnPolicy{
                std::make_shared<const RichonlineTimedBombRules>(RichonlineTimedBombRules::load(root)),0xa7,
                [this](std::uint8_t mover,std::int16_t position) {
                    check(static_cast<bool>(raw_authority),"timed_bomb_fixture_raw_authority_missing");
                    return raw_authority->timed_bomb_step_context(mover,position);
                }});
        }
        auto plan=make_richonline_boss_turns(startup,geometry(bank_junction,blocked_route),std::move(rules));
        raw_authority=attach_richonline_raw_authority(plan);
        raw_action=plan.action;
        session=std::make_unique<GameSession>(ClientVersion::richonline,make_richonline_game_callbacks(
            [this,plan=std::move(plan)](const GameAdmission& a)->std::optional<RichonlineStartupPlan> {
                return a==admission ? std::optional{plan} : std::nullopt;
            },[](std::size_t n){return Bytes(n,0x91);}));
        const auto init=delivered(session->feed(encode_frame(encode_game_admission(admission,ClientVersion::richonline),
            {Channel::game_c2s,{},ClientVersion::richonline})));
        check(init.size()==1 && opcode(init[0])==0x4000,"motion_admission_failed");
        send({0,0}); finish_move();
    }
    std::vector<Bytes> delivered(const std::vector<Bytes>& frames) {
        for(const auto& frame:frames) session->sent(frame);
        return decode(frames);
    }
    std::vector<Bytes> send(const Bytes& plain) {
        auto result=delivered(session->feed(encode_frame(richonline_board_frame(plain,{7,-2},Bytes(plain.size()+2,0x91)),
            {Channel::game_c2s,{},ClientVersion::richonline})));
        check(session->state()==GameState::admitted,"motion_flow_disconnected");
        record(result);
        return result;
    }
    void record(const std::vector<Bytes>& result) {
        for (const auto& b:result) {
            if(opcode(b)==0x4010) {++counter;last_move.reset();}
            if(opcode(b)==0x4011) last_move=b;
        }
    }
    std::vector<Bytes> poll() {
        auto result=delivered(session->poll());
        check(session->state()==GameState::admitted,"motion_poll_disconnected");
        record(result);
        return result;
    }
    std::vector<Bytes> card(std::uint16_t kind,std::uint8_t target) {
        const auto id=static_cast<std::int16_t>(kind+935);
        cards->commit_inventory(cards->prepare_add(id));
        std::uint8_t slot=0;while(cards->inventory()[slot].card_id!=id) ++slot;
        auto plain=request(kind,counter,slot,1);plain.push_back(0);plain.push_back(target);plain.push_back(0xcc);
        return send(plain);
    }
    std::vector<Bytes> roll() {return send(request(0x10,counter,0,4));}
    std::uint8_t add_card(std::int16_t id,std::int16_t count=1) {
        cards->commit_inventory(cards->prepare_add(id,count));
        std::uint8_t slot=0;
        while(slot<cards->inventory().size() && cards->inventory()[slot].card_id!=id) ++slot;
        check(slot<cards->inventory().size(),"test_card_not_inserted");
        return slot;
    }
    std::int16_t move_endpoint() const {
        check(last_move.has_value(),"motion_test_no_route");
        const auto& route=*last_move;
        auto position=static_cast<std::int32_t>(read_le(View(route).subspan(4,2)));
        for(std::size_t i=0;i<route[7];++i) {
            const auto direction=(route[11+i/4]>>(2*(i%4)))&3;
            position+=direction==1 ? -1 : direction==3 ? 1 : direction==0 ? 30 : -30;
        }
        return static_cast<std::int16_t>(position);
    }
    std::vector<Bytes> finish_move() {
        const auto position=move_endpoint();last_move.reset();
        return send(request(0x11,counter,static_cast<std::uint16_t>(position)));
    }
};
void reverse_and_self_stay(const std::filesystem::path& root) {
    Flow f(root);
    const auto reversed=f.card(105,0);
    check(reversed==std::vector<Bytes>{{0xb9,0x40,0x34,0x12,0,0,0}},"reverse_did_not_keep_roll_phase");
    f.roll();check(((*f.last_move)[11]&3)==1,"reverse_heading_not_used_by_roll");
    f.finish_move();f.finish_move();
    const auto position=f.landed[f.landed.size()-2].position;
    const auto held=f.card(106,0);
    check(held.size()==1 && opcode(held[0])==0x40ba && !f.last_move,"stay_fabricated_movement");
    const auto ended=f.send(request(0x11,f.counter,static_cast<std::uint16_t>(position)));
    check(ended.size()==4 && opcode(ended[0])==0x4013 && f.landed.back().actor_status.stay==1,
        "self_stay_did_not_resolve_current_tile");
    f.finish_move();
    const auto rolled=f.roll();check(rolled.size()==1 && opcode(rolled[0])==0x4011,"self_stay_did_not_expire");
}
void target_stay_waits_for_actual_stationary_report(const std::filesystem::path& root) {
    Flow f(root); const auto boss_position=f.landed.back().position;
    f.card(106,1);f.roll();const auto boss_turn=f.finish_move();
    check(boss_turn.size()==3 && opcode(boss_turn[1])==0x4010 && !f.last_move,
        "boss_stay_moved_or_skipped_real_stop_report");
    const auto human=f.send(request(0x11,f.counter,static_cast<std::uint16_t>(boss_position)));
    check(human.size()==3 && f.landed.back().actor_slot==1 && f.landed.back().actor_status.stay==1,
        "boss_stay_not_applied");
    f.roll(); f.finish_move();
    check(f.last_move && (*f.last_move)[8]==4,"boss_stay_did_not_expire_on_own_turn_end");
}
void turtle_duration_and_controlled_override(const std::filesystem::path& root) {
    Flow f(root);f.card(104,0);
    f.cards->commit_inventory(f.cards->prepare_add(1038));
    std::uint8_t slot=0;while(f.cards->inventory()[slot].card_id!=1038)++slot;
    auto chosen=request(103,f.counter,slot,1);chosen.insert(chosen.end(),{0,2,0xcc,0,0,0,0});
    const auto selected=f.send(chosen);
    check(selected.size()==2 && opcode(selected[0])==0x40b7 && (*f.last_move)[8]==2 && !f.logs.empty(),
        "controlled_die_did_not_follow_named_override_policy");
    f.finish_move();check(f.landed.back().actor_status.turtle==3,"self_turtle_duration_wrong");f.finish_move();
    for (std::uint8_t remaining=2;remaining>0;--remaining) {
        f.roll();check((*f.last_move)[8]==1,"turtle_did_not_force_one_step");
        f.finish_move();check(f.landed.back().actor_status.turtle==remaining,"turtle_decremented_on_wrong_actor");
        f.finish_move();
    }
    f.roll();check((*f.last_move)[8]==4,"turtle_did_not_expire_after_three_own_turns");
}
void target_turtle_affects_boss_next_route(const std::filesystem::path& root) {
    Flow f(root,false,3);f.card(104,1);f.roll();f.finish_move();
    check(f.last_move && (*f.last_move)[6]==1 && (*f.last_move)[8]==1,"target_turtle_did_not_affect_three_dice_boss");
    f.finish_move();check(f.landed.back().actor_status.turtle==3,"target_turtle_decremented_at_human_end");
}
void stationary_bank_keeps_final_junction(const std::filesystem::path& root) {
    Flow f(root,true);f.card(106,0);
    const auto open=f.send(request(0x11,f.counter,3));
    check(open.size()==2 && opcode(open[0])==0x4013 && opcode(open[1])==0x4018 && open[1][6]==0,
        "stationary_bank_not_opened_as_final_landing");
    auto bank_exit=request(0x27,f.counter,2);bank_exit.insert(bank_exit.end(),{0xcc,0xdd,0,0,0,0});
    const auto close=f.send(bank_exit);
    check(close.size()==1 && opcode(close[0])==0x402a && !f.last_move,"stay_bank_skipped_junction");
    auto direction=request(0x34,f.counter,3,1);direction.push_back(0xcc);
    const auto next=f.send(direction);
    check(next.size()==4 && opcode(next[0])==0x4035 && opcode(next[1])==0x4010,
        "stay_bank_junction_did_not_complete");
}
void fixed_step_cards_move_and_continue(const std::filesystem::path& root) {
    for(std::uint16_t kind=137;kind<=140;++kind) {
        Flow f(root);const auto slot=f.add_card(static_cast<std::int16_t>(kind+943),2);
        auto use=request(kind,f.counter,slot,1);use.push_back(0);
        const auto result=f.send(use);
        check(result.size()==2 && opcode(result[0])==kind+0x4050 && result[0].size()==6 &&
            result[0][4]==slot && result[0][5]==0 && opcode(result[1])==0x4011,
            "fixed_step_confirmation_or_movement_missing");
        const auto steps=static_cast<std::uint8_t>(kind-135);
        check((*f.last_move)[6]==1 && (*f.last_move)[7]==steps && (*f.last_move)[8]==steps &&
            f.cards->inventory()[slot].count==1,"fixed_step_distance_or_consumption_wrong");
        const auto next=f.finish_move();
        check(f.landed.back().position==3+steps && next.size()==4 && opcode(next[1])==0x4010,
            "fixed_step_landing_did_not_start_boss");
        f.finish_move();f.roll();
        check((*f.last_move)[8]==4,"fixed_step_persisted_into_next_turn");
    }
}
void fixed_step_turtle_policy(const std::filesystem::path& root) {
    Flow f(root);f.card(104,0);const auto slot=f.add_card(1083);
    auto use=request(140,f.counter,slot,1);use.push_back(0);
    f.send(use);check((*f.last_move)[8]==5 && !f.logs.empty(),"fixed_step_turtle_policy_not_applied");
    f.finish_move();check(f.landed.back().actor_status.turtle==3,"fixed_step_removed_turtle");
    f.finish_move();f.roll();check((*f.last_move)[8]==1,"fixed_step_extended_override_to_next_turn");
}
void selected_step_failure_preserves_inventory_and_phase(const std::filesystem::path& root) {
    for(const auto controlled:{false,true}) {
        Flow f(root,false,1,true);
        const auto slot=f.add_card(controlled ? 1038 : 1081);
        auto use=request(controlled ? 103 : 138,f.counter,slot,1);use.push_back(0);
        if(controlled) use.insert(use.end(),{3,0xcc,0,0,0,0});
        const auto before=f.cards->inventory();bool rejected=false;
        try {static_cast<void>(f.raw_action({},use));}
        catch(const CodecError& error) {rejected=std::string_view(error.what())=="richonline_route_static_effect_unsupported";}
        check(rejected && f.cards->inventory()==before,"failed_route_consumed_selected_step_card");
        const auto safe=f.add_card(1080);auto retry=request(137,f.counter,safe,1);retry.push_back(0);
        const auto result=f.send(retry);
        check(result.size()==2 && (*f.last_move)[8]==2,"failed_route_committed_movement_phase");
    }
}
void cosmetic_cards_restore_normal_action(const std::filesystem::path& root) {
    for(const auto kind:{154U,168U}) {
        Flow f(root);const auto slot=f.add_card(kind==154 ? 1127 : 1131);
        auto use=request(static_cast<std::uint16_t>(kind),f.counter,slot,1);use.push_back(0);
        const auto messages=f.send(use);
        check(messages.size()==1 && opcode(messages[0])==(kind==154 ? 0x40ea : 0x40f8) &&
            messages[0].size()==6 && messages[0][4]==slot && messages[0][5]==0 &&
            f.cards->inventory()[slot].count==0 && !f.last_move,"cosmetic_card_flow_incorrect");
        f.roll();check((*f.last_move)[8]==4,"cosmetic_card_did_not_preserve_normal_roll");
    }
}
std::size_t count_opcode(const std::vector<Bytes>& messages,std::uint16_t op) {
    return static_cast<std::size_t>(std::count_if(messages.begin(),messages.end(),
        [op](const Bytes& bytes){return opcode(bytes)==op;}));
}
void npc_fortune_continues_property_event(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,true);f.ground->place(7,{3,0x91,0x92});
    f.roll();const auto reward=f.finish_move();
    check(reward.size()==2 && opcode(reward[0])==0x4013 && opcode(reward[1])==0x4023 &&
        !f.last_move && f.landed.back().actor_status.possession==3,
        "fortune_skipped_following_property_wait_or_repeated_stop");
    check(f.cards->inventory()[0]==RichonlineChanceCardSlot{1038,1} &&
        f.cards->inventory()[1]==RichonlineChanceCardSlot{1044,1},"fortune_two_rewards_not_committed");
    const auto next=f.send(request(0x20,f.counter,0));
    check(next.size()==3 && opcode(next[0])==0x4010 && f.last_move,
        "fortune_followup_property_did_not_resume_turns");
}
void npc_roulette_continues_landing_once(const std::filesystem::path& root) {
    for(const std::int8_t npc:{std::int8_t{0},std::int8_t{1}}) {
        Flow f(root,false,1,false,true);f.ground->place(7,{npc,0x91,0x92});
        f.roll();const auto begin=f.finish_move();
        check(begin.size()==1 && opcode(begin[0])==0x4013 && f.landed.size()==1 && !f.last_move,
            "money_npc_did_not_wait_before_static_landing");
        auto roulette=request(34,f.counter,1,1);roulette.push_back(0xcc);
        const auto result=f.send(roulette);
        check(result.size()==4 && opcode(result[0])==0x4022 && count_opcode(result,0x4013)==0 &&
            opcode(result[1])==0x4010 && f.landed.size()==2 && f.landed.back().actor_status.possession==npc,
            "money_npc_did_not_resume_exact_landing");
        check(f.ledger->snapshot(0).funds.cash==(npc==0 ? 1020U : 980U) &&
            f.ledger->snapshot(1).funds.cash==(npc==0 ? 4980U : 5020U),"money_npc_transfer_incorrect");
        f.finish_move();f.roll();
    }
}
void npc_fortune_keeps_bank_and_junction(const std::filesystem::path& root) {
    Flow f(root,true,1,false,true);f.ground->place(3,{3,0x91,0x92});f.card(106,0);
    const auto open=f.send(request(0x11,f.counter,3));
    check(open.size()==3 && count_opcode(open,0x4013)==1 && opcode(open[1])==0x4023 &&
        opcode(open[2])==0x4018,"fortune_lost_bank_or_duplicated_stop");
    auto exit=request(0x27,f.counter,2);exit.insert(exit.end(),{0xcc,0xdd,0,0,0,0});
    const auto closed=f.send(exit);check(closed.size()==1 && opcode(closed[0])==0x402a,"fortune_bank_skipped_junction");
    auto direction=request(0x34,f.counter,3,1);direction.push_back(0xcc);
    check(f.send(direction).size()==4,"fortune_bank_junction_did_not_continue");
}
void npc_fortune_card_restores_roll(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true);const auto slot=f.add_card(1070);
    auto use=request(131,f.counter,slot,1);use.push_back(0);
    const auto reward=f.send(use);
    check(reward.size()==2 && opcode(reward[0])==0x40d3 && opcode(reward[1])==0x4023 && !f.last_move,
        "fortune_card_wrong_continuation");
    f.roll();f.finish_move();check(f.landed.back().actor_status.possession==3,"fortune_card_status_not_shared");
}
void npc_boss_money_needs_no_local_roulette(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true);f.ground->place(21,{0,0x91,0x92});
    f.roll();f.finish_move();const auto result=f.finish_move();
    check(result.size()==4 && opcode(result[0])==0x4013 && opcode(result[1])==0x4022 &&
        opcode(result[2])==0x4010 && f.landed.back().actor_slot==1 &&
        f.landed.back().actor_status.possession==0,"synthetic_money_waited_for_local_roulette");
    check(f.ledger->snapshot(0).funds.cash==980 && f.ledger->snapshot(1).funds.cash==5020,
        "synthetic_money_transfer_not_committed");
    f.roll();check(f.last_move.has_value(),"synthetic_money_did_not_restore_player_turn");
}
void npc_wealth_card_waits_then_restores_roll(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true);const auto slot=f.add_card(1069,2);
    auto use=request(130,f.counter,slot,1);use.push_back(0);
    const auto before=f.cards->inventory();auto stale=use;--stale[2];bool rejected=false;
    try {static_cast<void>(f.raw_action({},stale));}
    catch(const CodecError& error) {rejected=std::string_view(error.what())=="richonline_boss_wealth_card_counter_mismatch";}
    check(rejected && f.cards->inventory()==before,"stale_wealth_card_consumed_inventory");
    const auto opened=f.send(use);
    check(opened==std::vector<Bytes>{{0xd2,0x40,0x34,0x12,slot,0}} &&
        f.cards->inventory()[slot].count==1 && !f.last_move && f.ledger->snapshot(0).funds.cash==1000,
        "wealth_card_did_not_wait_for_money_result");
    auto roulette=request(34,f.counter,1,1);roulette.push_back(0xcd);
    const auto paid=f.send(roulette);
    check(paid==std::vector<Bytes>{{0x22,0x40,0x34,0x12,20,0,0}} && f.landed.size()==1 &&
        !f.last_move && f.ledger->snapshot(0).funds.cash==1020 && f.ledger->snapshot(1).funds.cash==4980,
        "wealth_card_money_finished_a_landing_or_turn");
    const auto balances=std::array{f.ledger->snapshot(0),f.ledger->snapshot(1)};
    check(f.send(roulette).empty() && f.ledger->snapshot(0)==balances[0] && f.ledger->snapshot(1)==balances[1],
        "duplicate_wealth_result_transferred_twice");
    f.roll();f.finish_move();check(f.landed.back().actor_status.possession==0,
        "wealth_card_status_not_available_to_landing");
}
void npc_roulette_timeout_and_late_request(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true);const auto slot=f.add_card(1069);
    auto use=request(130,f.counter,slot,1);use.push_back(0);f.send(use);
    f.now+=std::chrono::milliseconds{29999};check(f.session->poll().empty(),"npc_roulette_timed_out_early");
    f.now+=std::chrono::milliseconds{1};const auto paid=f.delivered(f.session->poll());
    check(paid==std::vector<Bytes>{{0x22,0x40,0x34,0x12,20,0,0}} &&
        f.session->state()==GameState::admitted && f.ledger->snapshot(0).funds.cash==1020,
        "npc_roulette_timeout_did_not_resolve_once");
    auto late=request(34,f.counter,1,1);late.push_back(0xcc);
    check(f.send(late).empty() && f.session->poll().empty() && f.ledger->snapshot(0).funds.cash==1020,
        "npc_roulette_late_request_recharged_or_disconnected");
    f.roll();check(f.last_move.has_value(),"npc_roulette_timeout_did_not_restore_roll");
}
void npc_summon_and_dismiss(const std::filesystem::path& root) {
    for(const auto target:{std::uint8_t{0},std::uint8_t{1}}) {
        Flow f(root,false,1,false,true);f.ground->place(11,{3,0x91,0x92});
        const auto slot=f.add_card(1047);auto summon=request(112,f.counter,slot,1);
        summon.insert(summon.end(),{0,target,0xdd});
        const auto before=f.cards->inventory();const auto ground=f.ground->snapshot();bool refused=false;
        try {static_cast<void>(f.raw_action({},summon));}
        catch(const CodecError& e) {refused=std::string_view(e.what())=="richonline_npc_session_visible_god_missing";}
        check(refused && f.cards->inventory()==before && f.ground->snapshot()==ground,
            "summon_selected_invisible_god_or_consumed_card");
        f.visible_npcs={11};const auto attached=f.send(summon);
        check(attached.size()==(target==0 ? 2U : 1U) &&
            attached[0]==Bytes({0xc0,0x40,0x34,0x12,slot,0,11,0,target}) &&
            (target!=0 || opcode(attached[1])==0x4023) && !f.ground->snapshot().objects.contains(11),
            "summon_target_effect_or_removed_ground_incorrect");
        const auto remove_slot=f.add_card(1048);auto dismiss=request(113,f.counter,remove_slot,1);
        dismiss.insert(dismiss.end(),{0,target,0xcc});f.visible_npcs.clear();
        const auto removed=f.send(dismiss);
        check(removed==std::vector<Bytes>{{0xc1,0x40,0x34,0x12,remove_slot,0,target}},
            "dismiss_requires_ground_or_wrong_wire");
        f.roll();f.finish_move();f.finish_move();
        check(!f.landed[f.landed.size()-(target==0 ? 2U : 1U)].actor_status.possession,
            "dismiss_did_not_clear_authoritative_attachment");
    }
}
std::vector<Bytes> summon_sleep(Flow& flow,std::uint8_t target) {
    flow.ground->place(11,{7,255,255});flow.visible_npcs={11};
    const auto slot=flow.add_card(1047);auto summon=request(112,flow.counter,slot,1);
    summon.insert(summon.end(),{0,target,0xcc});return flow.send(summon);
}
void npc_sleep_accepts_real_roll_and_expires(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,false,3,3,false,true);
    const auto attached=summon_sleep(f,0);
    check(attached.size()==1 && opcode(attached[0])==0x40c0 && !f.last_move,
        "npc7_summon_invented_roll_or_extra_effect");
    for(std::uint8_t turn=0;turn<3;++turn) {
        const auto rolled=f.roll();
        check(rolled.size()==1 && opcode(rolled[0])==0x4011 && (*f.last_move)[8]==4,
            "npc7_rejected_real_ordinary_roll");
        f.now+=std::chrono::milliseconds{30000};check(f.poll().empty(),"npc7_real_roll_timer_rerolled");
        f.finish_move();check(f.landed.back().actor_status.possession==7,"npc7_expired_on_other_actor");
        f.finish_move();
    }
    const auto slot=f.add_card(1127);auto use=request(154,f.counter,slot,1);use.push_back(0);
    check(opcode(f.send(use).front())==0x40ea,"npc7_did_not_restore_actions_after_resource_affix3");
    f.roll();f.finish_move();check(!f.landed.back().actor_status.possession,"npc7_clock_did_not_expire");
}
void npc_sleep_timeout_and_late_roll_are_once(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,false,3,3,false,true);summon_sleep(f,0);
    const auto calendar=f.counter;const auto late=request(0x10,calendar,0,4);
    f.now+=std::chrono::milliseconds{29999};check(f.poll().empty(),"npc7_recovery_timed_out_early");
    f.now+=std::chrono::milliseconds{1};const auto moved=f.poll();
    check(moved.size()==1 && opcode(moved[0])==0x4011 && f.last_move && !f.logs.empty(),
        "npc7_timeout_did_not_emit_ordinary_route");
    const auto accepted=*f.last_move;
    check(f.send(late).empty() && f.poll().empty() && f.last_move==accepted,
        "npc7_late_roll_rerolled_or_disconnected");
    bool rejected=false;
    try{static_cast<void>(f.raw_action({},request(0x10,calendar,1,4)));}
    catch(const CodecError&) {rejected=true;}
    check(rejected,"npc7_late_nonzero_parameter_was_accepted");
    f.finish_move();check(f.send(late).empty(),"npc7_late_roll_not_retained_across_boss_turn");
    f.finish_move();f.roll();check(f.last_move.has_value(),"npc7_timeout_prevented_next_controlled_turn");
}
void npc_sleep_disabled_actions_preserve_stores(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,false,3,3,false,true);summon_sleep(f,0);
    const auto slot=f.add_card(1080);const auto inventory=f.cards->inventory();
    const auto ground=f.ground->snapshot();const auto funds=f.ledger->snapshot(0);
    auto use=request(137,f.counter,slot,1);use.push_back(0);
    for(const auto& bytes:std::array{use,request(22,f.counter,3),request(0x10,f.counter,1,4)}) {
        bool rejected=false;
        try {static_cast<void>(f.raw_action({},bytes));}
        catch(const CodecError& error) {
            rejected=std::string_view(error.what())=="richonline_boss_controlled_action_forbidden" ||
                std::string_view(error.what())=="richonline_boss_roll_parameter_unsupported";
        }
        check(rejected && f.cards->inventory()==inventory && f.ground->snapshot()==ground &&
            f.ledger->snapshot(0)==funds && !f.last_move,"npc7_disabled_action_changed_shared_state");
    }
    auto malformed=use;malformed.push_back(0xff);bool wire_rejected=false;
    try {static_cast<void>(f.raw_action({},malformed));}
    catch(const CodecError& error) {wire_rejected=std::string_view(error.what())!="richonline_boss_controlled_action_forbidden";}
    check(wire_rejected,"npc7_disabled_action_skipped_schema_validation");
    f.roll();check(f.last_move.has_value(),"npc7_rejected_actions_lost_roll_phase");
}
void npc_sleep_skips_bank_checkpoint_and_final_junction(const std::filesystem::path& root) {
    Flow f(root,true,1,false,true,false,0,3,false,true);summon_sleep(f,0);
    f.controlled_fork_choice=1;
    f.roll();const auto ended=f.finish_move();
    check(f.landed.back().position==4 && f.landed.back().actor_status.possession==7 &&
        count_opcode(ended,0x4018)==0 && f.last_move,"npc7_passed_bank_requested_checkpoint");
    Flow at_junction(root,true,1,false,true,false,7,1,false,true);summon_sleep(at_junction,0);
    at_junction.roll();const auto completed=at_junction.finish_move();
    check(at_junction.landed.back().position==3 && count_opcode(completed,0x4018)==0 &&
        count_opcode(completed,0x4035)==0 && at_junction.last_move,
        "npc7_bank_landing_opened_bank_or_final_junction");
}
void npc_status_changes_preserve_or_detach_shared_clock(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true);f.ground->place(11,{3,255,255});f.visible_npcs={11};
    const auto slot=f.add_card(1047);auto summon=request(112,f.counter,slot,1);summon.insert(summon.end(),{0,0,0xcc});
    f.send(summon);f.card(104,0);
    f.status_transition=[](const RichonlineLandingContext& context)->std::optional<RichonlineLandingStatusChange> {
        if(context.actor_slot!=0) return {};
        auto after=context.actor_status;after.possession.reset();
        return RichonlineLandingStatusChange{context.actor_status,after};
    };
    f.roll();f.finish_move();f.finish_move();
    f.status_transition={};f.roll();f.finish_move();
    check(!f.landed.back().actor_status.possession && f.landed.back().actor_status.turtle==2,
        "motion_or_landing_change_desynchronized_or_extended_npc_clock");
}
void combat_packets_follow_boss_turn_before_roll(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,false,3,3,true);f.combat_rolls={90,0,0,0};
    f.roll();const auto next=f.finish_move();
    check(next.size()==6 && opcode(next[0])==0x4013 && opcode(next[1])==0x4010 &&
        opcode(next[2])==0x401e && opcode(next[3])==0x40bf && opcode(next[4])==0x420f &&
        opcode(next[5])==0x4011 && next[3][8]==1 && f.ledger->snapshot(0).funds.cash==900,
        "combat_packets_not_between_boss_turn_and_roll_or_damage_not_shared");
    f.combat_rolls={};f.finish_move();f.roll();
}
void combat_stepped_mine_continues_and_uses_endpoint(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,false,3,3,true);f.ground->place(7,{12,1,3});
    f.roll();const auto result=f.finish_move();
    check(count_opcode(result,0x4013)==1 && count_opcode(result,0x4017)==0 &&
        !f.ground->snapshot().objects.contains(7) && f.ledger->snapshot(0).funds.cash==950 &&
        f.landed.back().position==7 && f.last_move,"stepped_mine_not_mirrored_or_repeated_animation");
    f.finish_move();f.roll();
}
void combat_round_clock_red_and_expiry(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,false,3,3,true);f.ground->place(0,{12,1,3});
    for(std::uint8_t day=1;day<=3;++day) {
        f.roll();const auto result=f.finish_move();
        // This fixture refreshes one NPC every third complete round. Its401C
        // precedes the next4010; the mine tick must still follow that anchor.
        const auto anchor=day==3 ? std::size_t{2} : std::size_t{1};
        check(result.size()==(day==3 ? 7U : 5U) && opcode(result[0])==0x4013 &&
            count_opcode(result,0x401c)==(day==3 ? 1U : 0U) &&
            (day!=3 || opcode(result[1])==0x401c) && count_opcode(result,0x401e)==1 &&
            opcode(result[anchor])==0x4010 && result[anchor][4]==1 &&
            opcode(result[anchor+1])==0x401e && opcode(result[result.size()-2])==0x420f &&
            opcode(result.back())==0x4011,"mine_day_not_once_at_boss_round_anchor");
        if(day<3) check(f.ground->snapshot().objects.at(0).byte8==3-day &&
            count_opcode(result,0x4017)==0,"mine_red_day_or_countdown_incorrect");
        else check(!f.ground->snapshot().objects.contains(0) && count_opcode(result,0x4017)==1,
            "scheduled_mine_did_not_expire");
        f.finish_move();
    }
}
void combat_bankruptcy_stops_roll_and_delegates_terminal(const std::filesystem::path& root) {
    for(const auto mine:{false,true}) {
        Flow f(root,false,1,false,true,false,3,3,true);
        auto snapshot=f.ledger->snapshot(0);auto funds=snapshot.funds;funds.cash=20;funds.deposit=0;
        f.ledger->commit(0,snapshot,funds);
        if(mine) f.ground->place(7,{12,1,3});else f.combat_rolls={90,0,0,0};
        f.roll();const auto result=f.finish_move();
        check(f.terminal_calls.size()==1 && f.terminal_calls[0].bankrupt_actors==std::vector<std::uint8_t>{0} &&
            f.terminal_calls[0].reason==(mine ? RichonlineTerminalReason::stepped_mine : RichonlineTerminalReason::boss_attack) &&
            count_opcode(result,0x420f)==0 && count_opcode(result,0x4011)==0 &&
            f.ledger->snapshot(0).funds.cash==0 && f.session->poll().empty(),
            "combat_bankruptcy_continued_roll_or_failed_to_delegate_terminal");
        bool closed=false;
        try{static_cast<void>(f.raw_action({},request(0x10,f.counter,0,4)));}
        catch(const CodecError& error){closed=std::string_view(error.what())=="richonline_boss_session_closed";}
        check(closed,"combat_terminal_did_not_close_turn_owner");
    }
}
Bytes attack_request(std::uint16_t kind,std::uint16_t counter,std::uint8_t slot,std::int16_t position) {
    auto bytes=request(kind,counter,slot,1);bytes.push_back(0);
    append_le(bytes,static_cast<std::uint16_t>(position),2);
    if(kind!=109)bytes.insert(bytes.end(),{0,1});
    return bytes;
}
void combat_human_cards_restore_same_roll(const std::filesystem::path& root) {
    const std::array<std::uint16_t,4> kinds{109,111,124,133};
    const std::array<std::int16_t,4> cards{1044,1046,1063,1075};
    const std::array<std::uint16_t,4> confirmations{0x40bd,0x40bf,0x40cc,0x40d5};
    for(std::size_t i=0;i<kinds.size();++i) {
        Flow f(root,false,1,false,true,false,3,3,true);const auto slot=f.add_card(cards[i],2);
        const auto used=f.send(attack_request(kinds[i],f.counter,slot,23));
        check(used.size()==1 && opcode(used[0])==confirmations[i] && used[0][4]==slot && used[0][5]==0 &&
            (kinds[i]==109 || used[0][8]==0) && f.cards->inventory()[slot].count==1 &&
            !f.last_move && f.terminal_calls.empty(),"human_attack_card_looked_like_boss_or_advanced_turn");
        if(kinds[i]==109)check(f.ground->snapshot().objects.at(23)==RichonlineGroundObject{12,0,3},
            "human_mine_owner_or_duration_wrong");
        else check(f.ledger->snapshot(1).funds.cash==(kinds[i]==111 ? 4900U : 4800U),
            "human_projectile_damage_not_committed");
        f.roll();check(f.last_move.has_value(),"human_attack_card_did_not_restore_roll");
    }
}
void combat_human_projectile_terminal(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,false,3,3,true);const auto slot=f.add_card(1046);
    const auto snapshot=f.ledger->snapshot(1);auto funds=snapshot.funds;funds.cash=20;funds.deposit=0;
    f.ledger->commit(1,snapshot,funds);
    const auto result=f.send(attack_request(111,f.counter,slot,23));
    check(result.size()==2 && opcode(result[0])==0x40bf && f.terminal_calls.size()==1 &&
        f.terminal_calls[0].bankrupt_actors==std::vector<std::uint8_t>{1} &&
        f.terminal_calls[0].reason==RichonlineTerminalReason::human_attack && !f.last_move &&
        f.cards->inventory()[slot].count==0,"human_projectile_terminal_not_delegated");
}
Bytes timed_bomb_request(std::uint16_t counter,std::uint8_t slot,std::uint8_t target) {
    auto bytes=request(110,counter,slot,1);bytes.insert(bytes.end(),{0,target,0xcd});return bytes;
}
void attach_timed_bomb(Flow& flow,std::uint8_t target) {
    const auto slot=flow.add_card(1045);const auto response=flow.send(timed_bomb_request(flow.counter,slot,target));
    check(response==std::vector<Bytes>{{0xbe,0x40,0x34,0x12,slot,0,target,0xa7}} &&
        flow.cards->inventory()[slot].count==0 && !flow.last_move,"timed_bomb_card_wire_or_consumption_wrong");
}
void timed_bomb_counts_actual_steps_and_stops_once(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,false,3,3,true,false,true,0xfff0);attach_timed_bomb(f,0);
    for(std::uint8_t turn=0;turn<8;++turn) {
        f.roll();f.finish_move();
        check(f.landed.back().actor_status.timed_bomb==36-4*(turn+1) &&
            f.landed.back().actor_status.timed_bomb_owner==0,"timed_bomb_counted_days_or_wrong_steps");
        f.finish_move();
    }
    f.roll();const auto endpoint=f.move_endpoint();const auto stop=request(0x12,f.counter,static_cast<std::uint16_t>(endpoint));
    const auto before=f.ledger->snapshot(0);const auto ground=f.ground->snapshot();const auto inventory=f.cards->inventory();
    for(const auto& bad:std::array{request(0x11,f.counter,static_cast<std::uint16_t>(endpoint)),
        request(0x12,static_cast<std::uint16_t>(f.counter-1),static_cast<std::uint16_t>(endpoint)),
        request(0x12,f.counter,static_cast<std::uint16_t>(endpoint+1))}) {
        bool rejected=false;try{static_cast<void>(f.raw_action({},bad));}catch(const CodecError&){rejected=true;}
        check(rejected && f.ledger->snapshot(0)==before && f.ground->snapshot()==ground && f.cards->inventory()==inventory,
            "invalid_timed_bomb_report_committed_prefix_or_damage");
    }
    const auto result=f.send(stop);
    check(count_opcode(result,0x4013)==1 && count_opcode(result,0x4017)==0 &&
        f.landed.back().position==endpoint && !f.landed.back().actor_status.timed_bomb &&
        !f.landed.back().actor_status.timed_bomb_owner && f.ledger->snapshot(0).funds.cash==900 && f.last_move,
        "timed_bomb_survivor_failed_landing_or_repeated_animation");
    const auto settled=f.ledger->snapshot(0);const auto route=f.last_move;
    check(f.send(stop).empty() && f.ledger->snapshot(0)==settled && f.last_move==route,
        "duplicate_timed_bomb_stop_damaged_or_moved_twice");
    f.finish_move();check(f.send(stop).empty(),"late_timed_bomb_stop_lost_retirement");
    f.roll();f.finish_move();
}
void timed_bomb_early_explosion_keeps_ground_event(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,false,3,3,true,false,true);attach_timed_bomb(f,0);
    // Eight complete four-step moves consume32, then a fixed three-step card
    // consumes3. The following ordinary roll must stop after its first step.
    for(int turn=0;turn<8;++turn){f.roll();f.finish_move();f.finish_move();}
    const auto slot=f.add_card(1081);auto three=request(138,f.counter,slot,1);three.push_back(0);
    f.send(three);f.finish_move();check(f.landed.back().actor_status.timed_bomb==1,"timed_bomb_three_step_not_counted");
    const auto start=f.landed.back().position;f.finish_move();f.roll();
    const auto direction=(*f.last_move)[11]&3;
    const auto stop_position=static_cast<std::int16_t>(start+(direction==1 ? -1 : direction==3 ? 1 : direction==0 ? 30 : -30));
    check(stop_position!=f.move_endpoint(),"timed_bomb_fixture_did_not_stop_early");
    f.ground->place(stop_position,{3,255,255});
    const auto result=f.send(request(0x12,f.counter,static_cast<std::uint16_t>(stop_position)));
    check(count_opcode(result,0x4013)==1 && count_opcode(result,0x4023)==1 &&
        f.landed.back().position==stop_position && f.landed.back().actor_status.possession==3 &&
        !f.landed.back().actor_status.timed_bomb && f.last_move,
        "timed_bomb_early_stop_lost_npc_or_duplicated4013");
}
void timed_bomb_survivor_then_ground_mine(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,false,3,3,true,false,true);attach_timed_bomb(f,0);
    for(int turn=0;turn<8;++turn){f.roll();f.finish_move();f.finish_move();}
    f.roll();const auto endpoint=f.move_endpoint();f.ground->place(endpoint,{12,1,3});
    const auto result=f.send(request(0x12,f.counter,static_cast<std::uint16_t>(endpoint)));
    check(count_opcode(result,0x4013)==1 && count_opcode(result,0x4017)==0 &&
        !f.ground->snapshot().objects.contains(endpoint) && f.ledger->snapshot(0).funds.cash==850 &&
        f.landed.back().position==endpoint,"timed_bomb_landing_mine_lost_or_replayed_explosion");
}
void timed_bomb_boss_expiry_uses_actual_boss_report(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,false,3,3,true,false,true);attach_timed_bomb(f,1);
    for(int turn=0;turn<8;++turn) {
        f.roll();f.finish_move();f.finish_move();
        check(f.landed.back().actor_slot==1 && f.landed.back().actor_status.timed_bomb==36-4*(turn+1),
            "boss_timed_bomb_did_not_count_boss_steps");
    }
    f.roll();f.finish_move();const auto endpoint=f.move_endpoint();
    const auto result=f.send(request(0x12,f.counter,static_cast<std::uint16_t>(endpoint)));
    check(count_opcode(result,0x4013)==1 && f.landed.back().actor_slot==1 &&
        !f.landed.back().actor_status.timed_bomb && f.ledger->snapshot(1).funds.cash==4900 && !f.last_move,
        "boss_timed_bomb_did_not_return_to_human_roll");
    f.roll();
}
void timed_bomb_transfer_and_suppression(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,false,27,1,true,false,true);attach_timed_bomb(f,0);
    f.raw_authority->apply_s2c420c(gid,23);f.roll();f.finish_move();
    check(f.landed.back().position==23 && !f.landed.back().actor_status.timed_bomb,
        "timed_bomb_suppression_prevented_transfer");
    f.finish_move();
    check(f.landed.back().actor_slot==1 && f.landed.back().actor_status.timed_bomb==36 &&
        f.landed.back().actor_status.timed_bomb_owner==0,"transferred_timed_bomb_ignored_raw_suppression");
    Flow normal(root,false,1,false,true,false,27,1,true,false,true);attach_timed_bomb(normal,0);
    normal.roll();normal.finish_move();normal.finish_move();
    check(normal.landed.back().actor_slot==1 && normal.landed.back().actor_status.timed_bomb==28 &&
        normal.landed.back().actor_status.timed_bomb_owner==0,"normal_transferred_bomb_not_counted_by_raw_authority");
}
void timed_bomb_same_card_twice_is_deliberate_and_controlled_forbidden(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,false,3,3,true,true,true);const auto slot=f.add_card(1045,2);
    const auto card=timed_bomb_request(f.counter,slot,0);f.send(card);f.send(card);
    check(f.cards->inventory()[slot].count==0,"timed_bomb_identical_card_use_falsely_deduplicated");
    summon_sleep(f,0);const auto another=f.add_card(1045);const auto hand=f.cards->inventory();
    bool rejected=false;try{static_cast<void>(f.raw_action({},timed_bomb_request(f.counter,another,1)));}
    catch(const CodecError& e){rejected=std::string_view(e.what())=="richonline_boss_controlled_action_forbidden";}
    check(rejected && f.cards->inventory()==hand,"controlled_timed_bomb_consumed_card");
    f.roll();f.finish_move();check(f.landed.back().actor_status.timed_bomb==32 &&
        f.landed.back().actor_status.possession==7,"controlled_actor_did_not_count_real_movement");
}
void timed_bomb_bank_segment_counts_once(const std::filesystem::path& root) {
    Flow f(root,true,1,false,true,false,0,3,true,false,true);f.controlled_fork_choice=1;attach_timed_bomb(f,0);
    f.roll();const auto opened=f.send(request(0x28,f.counter,3));
    check(opcode(opened.front())==0x4018,"timed_bomb_bank_checkpoint_not_opened");
    auto exit=request(0x27,f.counter,2);exit.insert(exit.end(),{0xcc,0xdd,0,0,0,0});
    f.send(exit);f.finish_move();check(f.landed.back().position==4 && f.landed.back().actor_status.timed_bomb==32,
        "timed_bomb_bank_resume_recounted_authenticated_steps");
}
void timed_bomb_bankruptcy_does_not_land_or_roll(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,false,3,3,true,false,true);attach_timed_bomb(f,0);
    for(int turn=0;turn<8;++turn){f.roll();f.finish_move();f.finish_move();}
    auto funds=f.ledger->snapshot(0);auto low=funds.funds;low.cash=20;low.deposit=0;f.ledger->commit(0,funds,low);
    f.roll();const auto endpoint=f.move_endpoint();const auto count=f.landed.size();
    const auto stop=request(0x12,f.counter,static_cast<std::uint16_t>(endpoint));const auto result=f.send(stop);
    check(f.terminal_calls.size()==1 && f.terminal_calls[0].reason==RichonlineTerminalReason::timed_bomb &&
        f.terminal_calls[0].bankrupt_actors==std::vector<std::uint8_t>{0} && f.landed.size()==count &&
        count_opcode(result,0x4013)==0 && count_opcode(result,0x4011)==0 && f.ledger->snapshot(0).funds.cash==0,
        "timed_bomb_bankruptcy_landed_or_started_another_turn");
    check(f.raw_action({},stop).empty(),"terminal_timed_bomb_duplicate_not_retired");
}
void npc_rejects_unclosed_followup_before_mutation(const std::filesystem::path& root) {
    for(const std::int8_t npc:{std::int8_t{0},std::int8_t{3}}) {
        Flow f(root,false,1,false,true,false,27,1);f.reject_collision=true;f.ground->place(23,{npc,0x91,0x92});
        f.roll();const auto ground=f.ground->snapshot();const auto cards=f.cards->inventory();
        const auto funds=std::array{f.ledger->snapshot(0),f.ledger->snapshot(1)};
        bool rejected=false;
        try {static_cast<void>(f.raw_action({},request(0x11,f.counter,23)));}
        catch(const CodecError& error) {rejected=std::string_view(error.what())=="test_npc_collision_unimplemented";}
        check(rejected && f.ground->snapshot()==ground && f.cards->inventory()==cards &&
            f.ledger->snapshot(0)==funds[0] && f.ledger->snapshot(1)==funds[1],
            "npc_committed_before_unclosed_followup_rejection");
    }
}
void npc_synthetic_overlap_continues_shared_landing(const std::filesystem::path& root) {
    Flow f(root,false,1,false,true,false,27,1);f.ground->place(23,{3,0x91,0x92});
    f.roll();const auto result=f.finish_move();
    check(result.size()==5 && opcode(result[0])==0x4013 && opcode(result[1])==0x4023 &&
        count_opcode(result,0x4013)==1 && f.landed.back().occupied_by_other_actor &&
        f.landed.back().collision_resolved,"proven_boss_overlap_blocked_or_lost_physical_occupancy");
    f.finish_move();f.roll();
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_root_required");const std::filesystem::path root(argv[1]);
        reverse_and_self_stay(root);target_stay_waits_for_actual_stationary_report(root);
        turtle_duration_and_controlled_override(root);target_turtle_affects_boss_next_route(root);
        stationary_bank_keeps_final_junction(root);
        fixed_step_cards_move_and_continue(root);fixed_step_turtle_policy(root);
        selected_step_failure_preserves_inventory_and_phase(root);
        cosmetic_cards_restore_normal_action(root);
        npc_fortune_continues_property_event(root);npc_roulette_continues_landing_once(root);
        npc_fortune_keeps_bank_and_junction(root);npc_fortune_card_restores_roll(root);
        npc_boss_money_needs_no_local_roulette(root);
        npc_wealth_card_waits_then_restores_roll(root);
        npc_rejects_unclosed_followup_before_mutation(root);
        npc_synthetic_overlap_continues_shared_landing(root);
        npc_roulette_timeout_and_late_request(root);
        npc_summon_and_dismiss(root);
        npc_sleep_accepts_real_roll_and_expires(root);npc_sleep_timeout_and_late_roll_are_once(root);
        npc_sleep_disabled_actions_preserve_stores(root);npc_sleep_skips_bank_checkpoint_and_final_junction(root);
        npc_status_changes_preserve_or_detach_shared_clock(root);
        combat_packets_follow_boss_turn_before_roll(root);combat_stepped_mine_continues_and_uses_endpoint(root);
        combat_round_clock_red_and_expiry(root);combat_bankruptcy_stops_roll_and_delegates_terminal(root);
        combat_human_cards_restore_same_roll(root);combat_human_projectile_terminal(root);
        timed_bomb_counts_actual_steps_and_stops_once(root);timed_bomb_early_explosion_keeps_ground_event(root);
        timed_bomb_survivor_then_ground_mine(root);timed_bomb_boss_expiry_uses_actual_boss_report(root);
        timed_bomb_transfer_and_suppression(root);timed_bomb_same_card_twice_is_deliberate_and_controlled_forbidden(root);
        timed_bomb_bank_segment_counts_once(root);timed_bomb_bankruptcy_does_not_land_or_roll(root);
        std::cout<<"PASS encrypted motion/fixed-step cards, stationary landing, shared timers and prepare-before-consume\n";
    } catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}
}
