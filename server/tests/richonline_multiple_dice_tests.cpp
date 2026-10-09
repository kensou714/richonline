#include "richonline_boss_turns.hpp"
#include "richonline_boss_stage.hpp"
#include "richonline_motion_card.hpp"
#include "original_map.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool ok,const char* why){if(!ok)throw std::runtime_error(why);}
RichonlineBossStartup startup(){
    RichonlineBossStartup s{{3,25,{},{{1,25,0,true}}},
        {0x1234,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
            {{25,115,1,{7,7,7,7,7,7,7,7,7,7},0xb1},{-1,236,1,{},0xc1}}},
        {0x1234,0x4567,1,{{20000,0,150},{100000,0,0}}},{7,-2}};
    s.room.description.record[36]=3;return s;
}
Bytes request(std::uint16_t code,std::uint16_t calendar,std::uint32_t value,std::size_t width=2){
    Bytes out;append_le(out,code,2);append_le(out,calendar,2);append_le(out,value,width);return out;
}
RichonlineBossTurnRules rules(std::uint8_t count,std::vector<std::size_t> rolls){
    auto next=std::make_shared<std::size_t>(0);
    RichonlineBossTurnRules r{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
        [rolls=std::move(rolls),next](std::size_t limit){
            if(limit!=6)return std::size_t{0};
            return rolls[(*next)++%rolls.size()];
        },[](const RichonlineLandingContext&){return RichonlineLandingResult{{},RichonlineLandingProgress::complete};},
        [](View)->RichonlineLandingResult{throw CodecError("unexpected_multi_dice_event");}};
    r.boss_dice_count=count;return r;
}
void enable_payment(RichonlineBossTurnRules& rules,const std::filesystem::path& root){
    auto ledger=std::make_shared<RichonlineGameLedger>(
        std::vector<RichonlineGameFunds>{{20000,0,150,100000},{100000,0,0,{}}});
    rules.payment=std::make_shared<RichonlineGamePayment>(ledger,0,load_richonline_gold_charges(root/"Data/GoldCharge.kpd"),
        [](const GameGoldCharge&){return GameGoldChargeResult{GameChargeStatus::success,false,{}};});
    rules.payment_operation_prefix="multiple-dice-fixture";
}
void fields_and_route(const std::filesystem::path& root,std::uint8_t count){
    const auto map=load_richonline_road_topology(root/"Map/BS_1_1.emp");
    auto plan=make_richonline_boss_turns(startup(),map,rules(count,{0,2,5}));
    const auto open=plan.map_ready();check(open.size()==3,"multi_dice_opening");
    check(open[0][5]==1,"dice_count_overwrote_round_anchor");
    const auto& move=open[2];const int sum=count==1?1:count==2?4:10;
    check(move[6]==count && move[7]==sum && move[8]==1,"multi_dice_fields");
    if(count>=2)check(move[9]==3,"second_die_not_encoded");else check(move[9]==0xf9,"inactive_second_overwritten");
    if(count==3)check(move[10]==6,"third_die_not_encoded");else check(move[10]==9,"inactive_third_overwritten");
    const auto path=build_richonline_route(map,{236,1,sum,{}},[](std::size_t){return std::size_t{0};});
    for(std::size_t i=0;i<path.directions.size();++i)
        check(((move[11+i/4]>>(2*(i%4)))&3)==path.directions[i],"multi_dice_route_mismatch");
    const auto human=plan.action({},request(0x11,0x4568,static_cast<std::uint16_t>(path.landings.back())));
    check(human.size()==2 && human[0][4]==0,"multi_dice_boss_never_completed");
    const auto rolled=plan.action({},request(0x10,0x4569,0,4));
    check(rolled.size()==1 && rolled[0][6]==1,"boss_dice_count_leaked_to_human");
}
void maximum_and_bounds(const std::filesystem::path& root){
    const auto map=load_richonline_road_topology(root/"Map/BS_1_1.emp");
    auto plan=make_richonline_boss_turns(startup(),map,rules(3,{5}));
    const auto open=plan.map_ready();check(open[2][6]==3 && open[2][7]==18 && open[2][8]==6 &&
        open[2][9]==6 && open[2][10]==6,"max_three_dice_eighteen_route");
    for(const auto count:{std::uint8_t{0},std::uint8_t{4},std::uint8_t{255}}){
        try{make_richonline_boss_turns(startup(),map,rules(count,{0}));throw std::runtime_error("unsafe_count_accepted");}
        catch(const CodecError& e){check(std::string(e.what())=="richonline_boss_dice_count_invalid","wrong_count_error");}
    }
}
void stage_values(const std::filesystem::path& root){
    for(const auto& [name,expected]:std::vector<std::pair<std::string,std::uint32_t>>{
        {"BS_1_1.emp",1},{"BS_1_2.emp",2},{"BS_1_3.emp",3},{"BS_1_4.emp",3},
        {"BS_2_1.emp",2},{"BS_2_2.emp",2},{"BS_2_3.emp",3},{"BS_2_4.emp",3},
        {"BS_3_1.emp",3},{"BS_3_2.emp",3},{"BS_3_3.emp",3},{"BS_3_4.emp",3}})
        check(load_richonline_boss_stage(root,name).boss.max_dice==expected,"actual_stage_dice_changed");
    check(load_richonline_boss_stage(root,"V_BS_1_1.emp",2).boss.max_dice==3,"zhao_stage_dice_changed");
}
void human_selection_reproduction(const std::filesystem::path& root){
    const auto map=load_richonline_road_topology(root/"Map/BS_1_1.emp");
    auto policy=rules(1,{0});enable_payment(policy,root);
    auto plan=make_richonline_boss_turns(startup(),map,std::move(policy));
    plan.map_ready();
    const auto boss_route=build_richonline_route(map,{236,1,1,{}},[](std::size_t){return std::size_t{0};});
    plan.action({},request(0x11,0x4568,static_cast<std::uint16_t>(boss_route.landings.back())));
    check(plan.action({},Bytes{0x14,0,0x69,0x45,2,0xa7}).empty(),"dice_choice_invented_response");
    const auto rolled=plan.action({},request(0x10,0x4569,0,4));
    check(rolled.size()==1 && rolled[0][6]==2 && rolled[0][7]==2,"human_dice_selection_not_used");
}
RichonlineRoadTopology straight_map(){
    OriginalEmp emp{3,100,1,{},{},Bytes(6808,0xff),8,6408,0,0};
    for(std::size_t pos=0;pos<100;++pos) emp.payload[emp.terrain_offset+64*pos]=8;
    return richonline_road_topology(emp);
}
struct HumanFlow {
    std::unique_ptr<GameSession> session;
    std::shared_ptr<RichonlineBossCards> cards;
    std::function<std::vector<Bytes>(const Envelope299&,View)> action;
    const GameAdmission admission{0,3,25,{1,2,3,4,5,6,7,8},19,{}};
    std::uint16_t calendar=0x4567;
    Bytes movement;
    explicit HumanFlow(const std::filesystem::path& root){
        auto initial=startup();initial.init.participants[0].position=40;initial.init.participants[1].position=80;
        auto policy=rules(1,{5});
        enable_payment(policy,root);
        cards=std::make_shared<RichonlineBossCards>(std::make_shared<const RichonlineChanceResources>(
            RichonlineChanceResources::load(root)),0x1234,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}});
        policy.cards=cards;policy.motion_cards=std::make_shared<const RichonlineMotionCardRules>(RichonlineMotionCardRules::load(root));
        auto plan=make_richonline_boss_turns(initial,straight_map(),std::move(policy));action=plan.action;
        session=std::make_unique<GameSession>(ClientVersion::richonline,make_richonline_game_callbacks(
            [this,plan=std::move(plan)](const GameAdmission& value)->std::optional<RichonlineStartupPlan>{
                return value==admission?std::optional{plan}:std::nullopt;
            },[](std::size_t count){return Bytes(count,0x91);}));
        session->feed(encode_frame(encode_game_admission(admission,ClientVersion::richonline),
            {Channel::game_c2s,{},ClientVersion::richonline}));
        send({0,0});finish();
    }
    std::vector<Bytes> send(const Bytes& plain){
        const auto frames=session->feed(encode_frame(richonline_board_frame(plain,{7,-2},Bytes(plain.size()+2,0x91)),
            {Channel::game_c2s,{},ClientVersion::richonline}));
        std::vector<Bytes> result;
        for(const auto& bytes:frames){
            const auto frame=decode_frame(bytes,{Channel::game_s2c,{},ClientVersion::richonline});
            if(frame.wire_type==1)continue;
            auto response=decode_inner(decode_envelope(frame,ClientVersion::richonline).encoded);
            const auto op=read_le(View(response).first(2));
            if(op==0x4010){++calendar;movement.clear();}
            if(op==0x4011)movement=response;
            result.push_back(std::move(response));
        }
        check(session->state()==GameState::admitted,"human_dice_game_session_closed");return result;
    }
    void select(std::uint8_t count,std::uint8_t opaque=0xcc){
        auto choice=request(0x14,calendar,count,1);choice.push_back(opaque);
        check(send(choice).empty(),"human_dice_selection_generated_unrelated_packet");
    }
    void roll(){send(request(0x10,calendar,0,4));}
    void finish(){
        check(!movement.empty(),"human_dice_missing_route");
        auto endpoint=static_cast<std::int16_t>(read_le(View(movement).subspan(4,2)));
        for(std::size_t i=0;i<movement[7];++i){
            const auto direction=(movement[11+i/4]>>(2*(i%4)))&3;
            check(direction==1 || direction==3,"human_dice_nonhorizontal_route");
            endpoint=static_cast<std::int16_t>(endpoint+(direction==1?-1:1));
        }
        send(request(0x11,calendar,static_cast<std::uint16_t>(endpoint)));
    }
};
void encrypted_human_preferences_persist_and_respect_overrides(const std::filesystem::path& root){
    HumanFlow flow(root);
    for(const std::uint8_t count:std::array<std::uint8_t,4>{2,3,1,3}){
        flow.select(count,0xa7);flow.select(count,0xff);flow.roll();
        check(flow.movement[6]==count && flow.movement[7]==6*count,"human_multiple_dice_route_budget_wrong");
        for(std::uint8_t i=0;i<count;++i)check(flow.movement[8+i]==6,"human_multiple_dice_face_missing");
        flow.finish();check(flow.movement[6]==1,"human_selection_changed_boss_dice");flow.finish();
        flow.roll();check(flow.movement[6]==count,"human_selection_lost_next_turn");flow.finish();flow.finish();
    }
    flow.cards->commit_inventory(flow.cards->prepare_add(1080));
    flow.send(request(137,flow.calendar,0));
    check(flow.movement[6]==1 && flow.movement[7]==2,"fixed_step_did_not_override_human_dice");
    flow.finish();flow.finish();flow.roll();
    check(flow.movement[6]==3 && flow.movement[7]==18,"fixed_step_erased_human_preference");
    flow.finish();flow.finish();
    flow.cards->commit_inventory(flow.cards->prepare_add(1039));
    auto turtle=request(104,flow.calendar,0);turtle.insert(turtle.end(),{0,0xcc});flow.send(turtle);flow.roll();
    check(flow.movement[6]==1 && flow.movement[7]==1,"turtle_used_three_dice");
    flow.finish();flow.finish();
    for(unsigned turn=0;turn<2;++turn){
        flow.roll();check(flow.movement[6]==1 && flow.movement[7]==1,"turtle_duration_lost_dice_override");
        flow.finish();flow.finish();
    }
    flow.roll();check(flow.movement[6]==3 && flow.movement[7]==18,"turtle_expiry_erased_human_preference");
}
void selection_validation_is_atomic(const std::filesystem::path& root){
    HumanFlow flow(root);flow.select(2);
    for(const auto& bad:std::vector<Bytes>{request(0x14,static_cast<std::uint16_t>(flow.calendar-1),3),
        request(0x14,flow.calendar,0),request(0x14,flow.calendar,4),request(0x14,flow.calendar,0x0103)}){
        // A nonzero final byte is legal opaque sender data, not a high count byte.
        if(bad[4]==3 && bad[5]==1){check(flow.action({},bad).empty(),"dice_opaque_byte_rejected");flow.select(2);continue;}
        bool rejected=false;try{flow.action({},bad);}catch(const CodecError&){rejected=true;}
        check(rejected,"invalid_human_dice_choice_accepted");
    }
    flow.roll();check(flow.movement[6]==2,"invalid_choice_changed_preference");
    const auto before=flow.movement;
    check(flow.send(request(0x14,flow.calendar,3)).empty() && flow.movement==before,
        "dice_choice_replaced_pending_route");
    flow.finish();flow.finish();flow.roll();check(flow.movement[6]==3,"moving_choice_not_used_next_roll");
}
}
int main(int argc,char** argv){try{
    check(argc==2,"resource_root_required");const std::filesystem::path root(argv[1]);
    human_selection_reproduction(root);
    encrypted_human_preferences_persist_and_respect_overrides(root);selection_validation_is_atomic(root);
    stage_values(root);for(std::uint8_t n=1;n<=3;++n)fields_and_route(root,n);maximum_and_bounds(root);
    std::cout<<"PASS actual map dice policies, per-die4011 fields, summed routes and bounds\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
