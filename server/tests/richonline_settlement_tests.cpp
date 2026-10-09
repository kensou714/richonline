#include "richonline_settlement.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* error){if(!value)throw std::runtime_error(error);}
template<class F>void rejected(F fn){try{fn();}catch(const CodecError&){return;}throw std::runtime_error("missing_rejection");}
}
int main(){try{
    std::array<std::uint32_t,21> levels{};
    for(std::size_t i=0;i<levels.size();++i)levels[i]=static_cast<std::uint32_t>(i)*50;
    RichonlineBossStage stage{};stage.map_name="fixture.emp";stage.pawn_gold=100;
    stage.first_reward={10,20,0,{}};stage.repeat_reward={5,8,0,{}};
    const RichonlineBossSettlementRules rules{"explicit fixture policy",true,3,1,{2,0,0},{4,100,0}};
    const auto policy=richonline_boss_settlement_policy(stage,levels,rules);
    check(policy.first_win.gold_return==120 && policy.repeat_win.gold_return==108 && policy.first_win.experience==10 &&
        policy.repeat_win.experience==5 && policy.loss.experience==2 && policy.draw.gold_return==100,"resource_reward_mapping");
    stage.first_reward={10,20,1,{1125}};stage.repeat_reward={5,8,8,{4,200,201,202,203,204,205,206}};
    const auto raw_items=richonline_boss_settlement_policy(stage,levels,rules);
    check(raw_items.first_win.items->resource_count==1 && raw_items.first_win.items->resource_ids==std::vector<std::int32_t>{1125} &&
        raw_items.repeat_win.items->resource_count==8 && raw_items.repeat_win.items->resource_ids==stage.repeat_reward.item_ids,
        "resource_item_specifications_must_not_be_omitted_or_guessed");
    stage.first_reward.item_count=2;
    rejected([&]{(void)richonline_boss_settlement_policy(stage,levels,rules);});
    stage.first_reward={10,20,0,{}};stage.repeat_reward={5,8,0,{}};
    auto invalid_items=rules;invalid_items.loss.items=GameSettlementItemReward{1,{}};
    rejected([&]{(void)richonline_boss_settlement_policy(stage,levels,invalid_items);});
    auto no_return=rules;no_return.return_winning_pledge=false;
    check(richonline_boss_settlement_policy(stage,levels,no_return).first_win.gold_return==20,"pledge_rule_ignored");
    stage.first_reward.gold=2147483647U;
    rejected([&]{(void)richonline_boss_settlement_policy(stage,levels,rules);});
    stage.first_reward.gold=20;stage.first_reward.experience=32768;
    rejected([&]{(void)richonline_boss_settlement_policy(stage,levels,rules);});
    const auto finish=richonline_lobby_game_finished(0x1234);
    check(finish.wire_type==58 && finish.payload==Bytes({0x34,0x12,0,0}),"lobby_finish_wire_not_callback18");
    check(richonline_lobby_game_finished(32767).payload==Bytes({255,127,0,0}),"lobby_finish_room_limit");
    rejected([]{(void)richonline_lobby_game_finished(32768);});
    const GameSettlementResult persisted{false,true,{10,120,7},1,2,125,500,1,0,0};
    const std::array actors{RichonlineSettledActor{0,0,GameOutcome::win,false,0x63,persisted}};
    const std::array<std::int8_t,1> bankrupt{1};
    const auto output=plan_richonline_settlement(0x1234,bankrupt,actors,false);
    check(output.size()==4,"wrong_sequence_size");
    check(output[0]==Bytes({13,64,52,18,1}) && output[1]==Bytes({14,64,52,18,1}),"bankruptcy_sequence");
    check(output[2]==Bytes({27,64,52,18,0,0,10,0,120,0,0,0,7,0,0,0,1,0,0x63,1}),"result_fields");
    check(output[3]==Bytes({15,64,52,18,0}),"results_must_be_last");
    auto invalid=actors;invalid[0].slot=1;rejected([&]{(void)plan_richonline_settlement(1,bankrupt,invalid,false);});
    invalid=actors;invalid[0].escaped=true;rejected([&]{(void)plan_richonline_settlement(1,{},invalid,false);});
    invalid=actors;invalid[0].persisted.reward.experience=32768;rejected([&]{(void)plan_richonline_settlement(1,{},invalid,false);});
    const std::array duplicate{actors[0],actors[0]};rejected([&]{(void)plan_richonline_settlement(1,{},duplicate,false);});
    rejected([&]{(void)plan_richonline_settlement(1,{}, {},false);});
    std::cout<<"PASS settlement ordering and explicit persisted reward fields\n";
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
