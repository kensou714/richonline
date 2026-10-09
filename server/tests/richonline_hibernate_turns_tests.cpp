#include "richonline_boss_cards.hpp"
#include "richonline_combat_bridge.hpp"
#include "richonline_boss_stage.hpp"
#include "richonline_npc_session.hpp"
#include "richonline_raw_authority.hpp"
#include "original_map.hpp"
#include <algorithm>
#include <iostream>

namespace {
using namespace richnet;
constexpr std::uint16_t game=0x1234;
void check(bool value,const char* why) {if(!value) throw std::runtime_error(why);}
std::uint16_t opcode(const Bytes& bytes) {return static_cast<std::uint16_t>(read_le(View(bytes).first(2)));}
Bytes request(std::uint16_t op,std::uint16_t calendar,std::uint32_t argument,std::size_t width=2) {
    Bytes bytes;append_le(bytes,op,2);append_le(bytes,calendar,2);append_le(bytes,argument,width);return bytes;
}
RichonlineRoadTopology geometry() {
    OriginalEmp emp{3,30,1,{},{},Bytes(8+68*30,0xff),8,8+64*30,0,0};
    for(std::size_t pos=0;pos<30;++pos) if(pos<=12 || pos>=20) emp.payload[emp.terrain_offset+64*pos]=8;
    return richonline_road_topology(emp);
}
struct Flow {
    std::shared_ptr<const RichonlineChanceResources> resources;
    std::shared_ptr<RichonlineBossCards> cards;
    std::shared_ptr<RichonlineGameLedger> ledger;
    std::shared_ptr<RichonlineGroundObjects> ground;
    std::array<RichonlineRawActorState,2> raw{{{-1,-1,-1,-1,true},{-1,-1,-1,-1,true}}};
    std::function<RichonlineRawActorState(std::uint8_t)> raw_projection;
    std::function<std::vector<Bytes>(const Envelope299&,View)> raw_action;
    std::function<std::optional<RichonlineLandingStatusChange>(const RichonlineLandingContext&)> change;
    std::vector<RichonlineLandingContext> landed;
    std::unique_ptr<GameSession> session;
    GameAdmission admission{0,3,25,{1,2,3,4,5,6,7,8},19,{}};
    std::chrono::steady_clock::time_point now{};
    std::uint16_t calendar=0x4567;
    std::optional<Bytes> movement;
    std::size_t boss_attacks=0,random_draws=0;
    explicit Flow(const std::filesystem::path& root,bool npcs=false,bool combat=false) {
        resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
        cards=std::make_shared<RichonlineBossCards>(resources,game,
            RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}});
        RichonlineChanceInventory hand{};hand[0]={506,2};cards->commit_inventory(hand);
        RichonlineBossStartup startup{{3,25,{},{{1,25,0,true}}},
            {game,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
                {{25,3,3,{7,7,7,7,7,7,7,7,7,7},0xb1},{-1,27,1,{},0xc1}}},
            {game,calendar,1,{{20000,0,150},{100000,0,0}}},{7,-2}};
        startup.room.description.record[36]=3;
        RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
            [this](std::size_t bound) {++random_draws;check(bound==1 || bound==6,"hibernate_fixture_unexpected_random");
                return bound==6 ? std::size_t{3}:std::size_t{0};},
            [this](const RichonlineLandingContext& ctx) {
                landed.push_back(ctx);
                return RichonlineLandingResult{{request(0x4013,game,static_cast<std::uint16_t>(ctx.position))},
                    RichonlineLandingProgress::complete,{},change ? change(ctx):std::nullopt};
            },[](View)->RichonlineLandingResult {throw CodecError("hibernate_fixture_unexpected_event");}};
        rules.cards=cards;rules.now=[this]{return now;};
        rules.hibernate=std::make_shared<const RichonlineHibernateTurnPolicy>(RichonlineHibernateTurnPolicy{
            resources,RichonlineHibernateRules::load(root),[this](std::uint8_t actor){
                return raw_projection ? raw_projection(actor):raw.at(actor);}});
        if(npcs || combat) {
            rules.npc_landing_preflight=[](const RichonlineLandingContext& context) {
                if(context.occupied_by_other_actor && !context.collision_resolved)
                    throw CodecError("hibernate_fixture_unresolved_collision");
            };
            ledger=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{20000,0,150,{}},{100000,0,0,{}}});
            std::vector<std::int16_t> positions;
            for(std::int16_t pos=0;pos<30;++pos) if(pos<=12 || pos>=20) positions.push_back(pos);
            ground=std::make_shared<RichonlineGroundObjects>(std::move(positions));
            rules.ledger=ledger;rules.ground=ground;
        }
        if(npcs) {
            RichonlineNpcSessionPolicy policy{{0,0,0,5,1000,{0,1,3},0x91,0x92,0x93,0x94,false},
                19,{1038,1044},{25,-1},{load_richonline_npc_affix(root,0),load_richonline_npc_affix(root,1)},
                "hibernate-test-fixed-20",[](std::uint8_t,std::int8_t,const auto&){return std::int16_t{20};}};
            rules.npcs=std::make_shared<RichonlineNpcSession>(game,"BS_1_1.emp",RichonlineNpcRules::load(root),resources,
                std::make_shared<const RichonlineChanceEventTable>(RichonlineChanceEventTable::load(root)),
                ledger,cards,ground,std::move(policy));
        }
        if(combat) {
            auto property=std::make_shared<RichonlineBossProperty>(root,game,ledger,load_richonline_boss_stage(root,"BS_1_1.emp"));
            const auto topology=load_richonline_road_topology(root/"Map"/"BS_1_1.emp");
            RichonlineCombatWorld world;
            world.width=static_cast<std::uint16_t>(topology.width());world.height=static_cast<std::uint16_t>(topology.height());
            world.resources={50,100,200,100,200,3,1,1,1,1};
            world.step=[width=world.width,height=world.height](std::int16_t pos,std::uint8_t direction)->std::optional<std::int16_t> {
                const auto x=pos%width,y=pos/width;
                if(direction==0 && x>0)return static_cast<std::int16_t>(pos-1);
                if(direction==1 && x+1<width)return static_cast<std::int16_t>(pos+1);
                if(direction==2 && y>0)return static_cast<std::int16_t>(pos-width);
                if(direction==3 && y+1<height)return static_cast<std::int16_t>(pos+width);
                return {};
            };
            world.targets=[](std::uint8_t,RichonlineCombatEffect,const RichonlineCombatSessionView& state) {
                return std::vector<std::int16_t>{state.actors[0]->position};
            };
            world.resolve_terms=[](const RichonlineCombatActorView&,const RichonlineCombatSessionView&) {
                return RichonlineCombatWorld::ResolvedTerms{{},{},0,0};
            };
            world.building=[property](const RichonlineCombatBuildingView& before,RichonlineBossBlastBuildingEffect effect) {
                return property->combat_building_effect(before,effect);
            };
            rules.combat=std::make_shared<RichonlineCombatBridge>(game,ledger,cards,ground,property,std::move(world),RichonlineBossCombatPolicy{});
            rules.combat_random=[this] {++boss_attacks;return RichonlineBossAttackRandomness{{},[](std::size_t){return std::size_t{0};}};};
            rules.combat_capabilities=[](std::uint8_t,const RichonlineActorStatus&) {
                return RichonlineCombatCapabilities{true,false,false,false,true};
            };
            rules.terminal=[](const RichonlineTurnTerminalContext&)->RichonlineTurnTerminalResult {
                throw CodecError("hibernate_fixture_unexpected_bankruptcy");
            };
        }
        auto plan=make_richonline_boss_turns(startup,geometry(),std::move(rules));raw_action=plan.action;
        session=std::make_unique<GameSession>(ClientVersion::richonline,make_richonline_game_callbacks(
            [this,plan=std::move(plan)](const GameAdmission& value)->std::optional<RichonlineStartupPlan> {
                return value==admission ? std::optional{plan}:std::nullopt;
            },[](std::size_t size){return Bytes(size,0x91);}));
        check(delivered(session->feed(encode_frame(encode_game_admission(admission,ClientVersion::richonline),
            {Channel::game_c2s,{},ClientVersion::richonline}))).size()==1,"hibernate_admission_failed");
        send({0,0});finish();
    }
    std::vector<Bytes> delivered(const std::vector<Bytes>& frames) {
        std::vector<Bytes> result;
        for(const auto& bytes:frames) {
            session->sent(bytes);
            const auto frame=decode_frame(bytes,{Channel::game_s2c,{},ClientVersion::richonline});
            if(frame.wire_type!=1) result.push_back(decode_inner(decode_envelope(frame,ClientVersion::richonline).encoded));
        }
        for(const auto& bytes:result) {
            if(opcode(bytes)==0x4010) {++calendar;movement.reset();}
            if(opcode(bytes)==0x4011) movement=bytes;
        }
        return result;
    }
    std::vector<Bytes> send(const Bytes& plain) {
        auto result=delivered(session->feed(encode_frame(richonline_board_frame(plain,{7,-2},Bytes(plain.size()+2,0x91)),
            {Channel::game_c2s,{},ClientVersion::richonline})));
        check(session->state()==GameState::admitted,"hibernate_session_disconnected");return result;
    }
    std::vector<Bytes> poll() {
        auto result=delivered(session->poll());check(session->state()==GameState::admitted,"hibernate_poll_disconnected");return result;
    }
    Bytes hibernate() const {auto bytes=request(164,calendar,0,1);bytes.push_back(0);return bytes;}
    std::vector<Bytes> roll() {return send(request(0x10,calendar,0,4));}
    std::vector<Bytes> finish() {
        check(movement.has_value(),"hibernate_fixture_missing_route");const auto& bytes=*movement;
        auto position=static_cast<std::int32_t>(read_le(View(bytes).subspan(4,2)));
        for(std::size_t i=0;i<bytes[7];++i) {
            const auto direction=(bytes[11+i/4]>>(2*(i%4)))&3;
            position+=direction==1 ? -1:direction==3 ? 1:direction==0 ? 30:-30;
        }
        movement.reset();return send(request(0x11,calendar,static_cast<std::uint16_t>(position)));
    }
    void rejected(const Bytes& packet) {
        const auto before=cards->inventory();bool failed=false;
        try {static_cast<void>(raw_action({},packet));}catch(const CodecError&){failed=true;}
        check(failed && cards->inventory()==before,"hibernate_invalid_request_mutated_inventory");
    }
};
void skipped(const std::vector<Bytes>& packets,std::uint8_t actor,bool stop,bool mine_day=false) {
    const std::size_t offset=stop ? 1U:0U;
    const std::size_t extra=mine_day ? 1U:0U;
    if(packets.size()!=offset+extra+2) {
        std::cerr<<"expected skipped actor="<<static_cast<unsigned>(actor)<<" opcodes:";
        for(const auto& packet:packets)std::cerr<<' '<<std::hex<<opcode(packet);
        std::cerr<<std::dec<<'\n';
    }
    check(packets.size()==offset+extra+2 && (!stop || opcode(packets[0])==0x4013) &&
        opcode(packets[offset])==0x4010 && packets[offset][4]==actor &&
        (!mine_day || opcode(packets[offset+1])==0x401e) && opcode(packets.back())==0x420f,
        "hibernate_skip_emitted_move_attack_or_wrong_actor");
}
void frozen_boss_skips_once_and_duplicate_is_idempotent(const std::filesystem::path& root) {
    Flow f(root,false,true);const auto use=f.hibernate();
    check(f.send(use)==std::vector<Bytes>{{0xf4,0x40,0x34,0x12,0,0}} && f.cards->inventory()[0].count==1,
        "hibernate_exact_wire_or_consumption_incorrect");
    check(f.send(use).empty() && f.cards->inventory()[0].count==1,"hibernate_duplicate_consumed_twice");
    auto changed=use;changed[5]=1;f.rejected(changed);
    f.roll();const auto attacks=f.boss_attacks,draws=f.random_draws;
    skipped(f.finish(),1,true,true);
    check(!f.movement && f.boss_attacks==attacks && f.random_draws==draws,"frozen_boss_executed_ai_or_dice");
    f.now+=std::chrono::milliseconds{1799};check(f.poll().empty(),"frozen_boss_timeout_early");
    f.now+=std::chrono::milliseconds{1};skipped(f.poll(),0,false);
    check(f.poll().empty() && !f.movement,"frozen_boss_timeout_advanced_twice");
    check(f.send(use).empty() && f.cards->inventory()[0].count==1,"late_hibernate_replay_consumed_again");
    f.roll();const auto resumed=f.finish();
    check(resumed.size()==5 && opcode(resumed[1])==0x4010 && resumed[1][4]==1 && opcode(resumed[2])==0x401e &&
        opcode(resumed.back())==0x4011 && f.boss_attacks==attacks+1,"boss_did_not_resume_on_freeze_one_to_zero");
    f.finish();check(f.landed.back().actor_slot==1 && f.landed.back().actor_status.frozen==0,"boss_freeze_not_expired");
}
void validation_preserves_action_and_inventory(const std::filesystem::path& root) {
    Flow f(root);auto stale=f.hibernate();--stale[2];f.rejected(stale);
    auto long_packet=f.hibernate();long_packet.push_back(0);f.rejected(long_packet);
    auto bad_slot=f.hibernate();bad_slot[4]=8;f.rejected(bad_slot);
    auto wrong_card=f.hibernate();wrong_card[4]=1;f.rejected(wrong_card);
    const std::array fields{&RichonlineRawActorState::hotel1493,&RichonlineRawActorState::hospital1494,
        &RichonlineRawActorState::jail1495,&RichonlineRawActorState::kidnapped1497};
    for(auto& actor:f.raw) for(const auto field:fields) {
        (actor.*field).reset();f.rejected(f.hibernate());actor.*field=0;f.rejected(f.hibernate());actor.*field=-1;
    }
    check(f.send(f.hibernate()).size()==1,"hibernate_rejection_lost_action_phase");
    f.roll();auto during_move=f.hibernate();during_move[4]=1;f.rejected(during_move);skipped(f.finish(),1,true);
}
void human_freeze_preserves_npc_clock(const std::filesystem::path& root) {
    Flow f(root,true);const auto duration=RichonlineNpcRules::load(root).fortune_affix_turns;
    check(duration>=3,"hibernate_fixture_fortune_duration_short");
    f.cards->commit_inventory(f.cards->prepare_add(1070));
    std::uint8_t slot=0;while(f.cards->inventory()[slot].card_id!=1070) ++slot;
    auto fortune=request(131,f.calendar,slot,1);fortune.push_back(0);f.send(fortune);
    bool injected=false;
    f.change=[&](const RichonlineLandingContext& ctx)->std::optional<RichonlineLandingStatusChange> {
        if(ctx.actor_slot!=0 || injected)return {};
        injected=true;auto after=ctx.actor_status;after.frozen=2;after.turtle=3;
        return RichonlineLandingStatusChange{ctx.actor_status,after};
    };
    f.roll();f.finish();skipped(f.finish(),0,true);
    check(f.landed[f.landed.size()-2].actor_status.possession==3,"human_freeze_lost_initial_possession");
    f.now+=std::chrono::milliseconds{1799};check(f.poll().empty(),"human_freeze_timeout_early");
    f.now+=std::chrono::milliseconds{1};const auto boss=f.poll();
    check(boss.size()==3 && opcode(boss[0])==0x4010 && boss[0][4]==1 && opcode(boss.back())==0x4011,
        "human_freeze_did_not_advance_boss");
    f.finish();f.roll();
    check(f.movement && (*f.movement)[8]==1,"human_freeze_lost_unrelated_turtle_status");
    f.finish();check(f.landed.back().actor_slot==0 && f.landed.back().actor_status.frozen==0 &&
        f.landed.back().actor_status.possession==3,"human_freeze_or_npc_clock_desynchronized");
    // The skipped own turn counts toward possession: the duration is not
    // extended merely because that actor had no movement/landing report.
    for(std::uint8_t own_turn=2;own_turn<duration;++own_turn) {
        f.finish();f.roll();f.finish();
        check(f.landed.back().actor_status.possession==(own_turn+1==duration ? std::optional<std::int8_t>{}:std::optional<std::int8_t>{3}),
            "frozen_human_npc_own_turn_clock_drift");
    }
}
void changed_authority_is_rejected_before_commit(const std::filesystem::path& root) {
    Flow f(root);std::size_t boss_reads=0;
    f.raw_projection=[&](std::uint8_t actor) {
        auto value=f.raw.at(actor);
        if(actor==1 && ++boss_reads==2)value.hospital1494=0;
        return value;
    };
    f.rejected(f.hibernate());check(boss_reads==2,"hibernate_snapshot_not_rechecked");
    f.raw_projection={};
    check(f.send(f.hibernate()).size()==1 && f.cards->inventory()[0].count==1,"hibernate_stale_commit_lost_retry");
    f.roll();skipped(f.finish(),1,true);
}
}
int main(int argc,char** argv) {
    try {
        if(argc!=2)return 2;const auto root=std::filesystem::path(argv[1]);
        frozen_boss_skips_once_and_duplicate_is_idempotent(root);
        validation_preserves_action_and_inventory(root);human_freeze_preserves_npc_clock(root);
        changed_authority_is_rejected_before_commit(root);
        std::cout<<"PASS encrypted NEW164/40F4 hibernate turns, AI suppression, timeout, replay and NPC clocks\n";
    }catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
