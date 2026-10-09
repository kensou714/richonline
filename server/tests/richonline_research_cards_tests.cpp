#include "richonline_research_cards.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool condition,const char* why) {if(!condition) throw std::runtime_error(why);}
template<class F> void rejects(F f) {try{f();}catch(const CodecError&){return;}throw std::runtime_error("expected rejection");}
RichonlineResearchCardContext context(){return {7,8,0,0,true,true};}
RichonlineChanceInventory inventory(std::int16_t id){RichonlineChanceInventory result{};result[2]={id,2};return result;}
RichonlineResearchTrapRules rules(){return {3,1,3};}
RichonlineResearchCardRequest request(std::uint8_t code,std::uint8_t target=12){return decode_richonline_research_card(Bytes{code,0,8,0,2,0,target,0});}
void exact_wire(){
    for(std::uint8_t code=155;code<=157;++code){
        Bytes input{code,0,8,0,2,0,code==156?std::uint8_t{1}:std::uint8_t{12},0xcc};
        if(code!=156) input[7]=0;
        const auto decoded=decode_richonline_research_card(input);auto expected=input;expected[0]=static_cast<std::uint8_t>(code+80);expected[1]=0x40;expected[2]=7;
        check(encode_richonline_research_card_success(7,decoded)==expected,"wire mismatch");
        input.push_back(0);rejects([&]{(void)decode_richonline_research_card(input);});
    }
    rejects([]{(void)request(156,0);});rejects([]{(void)decode_richonline_research_card(Bytes{155,0,8,0,8,0,12,0});});
    rejects([]{(void)decode_richonline_research_card(Bytes{155,0,8,0,2,1,12,0});});
    rejects([]{(void)decode_richonline_research_card(Bytes{155,0,8,0,2,0,255,255});});
}
void traps(){
    const auto parsed=RichonlineResearchTrapRules::parse("[ITEM]\nindx=13\nvalue=3\n[ITEM]\nindx=26\nvalue=1\n[ITEM]\nindx=27\nvalue=3\n");
    check(parsed.freeze_timer==3 && parsed.fire_radius==1 && parsed.fire_rounds==3,"resource rules");
    rejects([]{(void)RichonlineResearchTrapRules::parse("[ITEM]\nindx=13\nvalue=0\n");});
    auto hand=inventory(1181);RichonlineGroundSnapshot ground{{},9};
    RichonlineResearchTrapMap map{5,5,true,[](std::int16_t){return RichonlineResearchTrapCell{true,false,8};},0};
    auto ice=plan_richonline_research_trap(request(155),context(),map,rules(),hand,ground);
    check(ice.after_ground.at(12)==RichonlineGroundObject{25,255,255} && ice.after_inventory[2].count==1,"ice placement");
    RichonlineActorStatus status{};const RichonlineGroundSnapshot placed{ice.after_ground,10};
    auto landing=plan_richonline_ice_trap_landing(12,placed,status,rules());
    check(landing.after_ground.empty() && landing.after_status.frozen==3,"ice consumption/timer");
    status.protected_from_status=true;status.frozen=7;
    landing=plan_richonline_ice_trap_landing(12,placed,status,rules());
    check(landing.after_ground.empty() && landing.after_status.frozen==7 && landing.protected_from_freeze,"protected ice consumed");
    map.cell=[](std::int16_t p){return RichonlineResearchTrapCell{true,p==13,static_cast<std::int8_t>(p==11?28:p==7?2:8)};};
    ground.objects.emplace(6,RichonlineGroundObject{12,1,2});
    auto fire=plan_richonline_research_trap(request(157),context(),map,rules(),inventory(1183),ground);
    check(fire.after_ground.size()==7 && fire.after_ground.at(7)==RichonlineGroundObject{26,0,3},"fire skips occupancy but permits type2");
    check(fire.after_ground.at(6)==ground.objects.at(6) && !fire.after_ground.contains(11) && !fire.after_ground.contains(13),"fire overwrite");
    map.fire_owner=-1;auto corner=plan_richonline_research_trap(request(157,0),context(),map,rules(),inventory(1183),RichonlineGroundSnapshot{{},3});
    check(corner.after_ground.size()==4 && corner.after_ground.at(0).byte7==255,"clipped fire neutral owner");
    map.cell=[](std::int16_t){return RichonlineResearchTrapCell{false,false,8};};
    auto empty=plan_richonline_research_trap(request(157),context(),map,rules(),inventory(1183),ground);
    check(empty.after_ground==ground.objects && empty.after_inventory[2].count==1,"empty fire still consumes as client does");
    rejects([&]{(void)plan_richonline_research_trap(request(155),context(),map,rules(),hand,ground);});
    auto wrong=context();wrong.calendar=9;rejects([&]{(void)plan_richonline_research_trap(request(155),wrong,map,rules(),hand,ground);});
    check(hand[2].count==2 && ground.objects.size()==1,"planner mutated input");
    const RichonlineGroundSnapshot clocks{{{1,{26,0,3}},{2,{26,1,1}},{3,{26,255,1}},{4,{25,255,255}}},20};
    const std::array<bool,2> active{true,true};
    auto tick=plan_richonline_fire_trap_tick(clocks,1,false,active);
    check(tick.after_ground.at(1).byte8==3 && !tick.after_ground.contains(2) && tick.after_ground.contains(3),"owner-specific fire clock");
    tick=plan_richonline_fire_trap_tick(clocks,0,true,active);
    check(tick.after_ground.at(1).byte8==2 && tick.after_ground.at(2).byte8==1 && !tick.after_ground.contains(3),"neutral anchor fire clock");
    const std::array<bool,2> inactive{true,false};
    tick=plan_richonline_fire_trap_tick(clocks,0,true,inactive);
    check(!tick.after_ground.contains(2) && tick.after_ground.at(4).npc==25,"inactive owner fire clock");
    const auto damage=plan_richonline_fire_trap_damage(1,{{500,1000,30,40},1},2000);
    check(damage.after.cash==0 && damage.after.deposit==0 && damage.after.tickets==30,"fire funds mirror");
}
void poison(){
    const auto footprint=richonline_poison_footprint(12,3,[](std::int16_t p,std::uint8_t direction)->std::optional<std::int16_t>{
        int x=p%5,y=p/5;switch(direction){case 0:--x;break;case 1:++x;break;case 2:--y;break;case 3:++y;break;default:throw std::runtime_error("direction");}
        if(x<0 || x>=5 || y<0 || y>=5)return std::nullopt;return static_cast<std::int16_t>(y*5+x);
    });
    check(footprint.size()==9 && footprint[1].attenuation_layer==0 && footprint[5].attenuation_layer==1,"poison ray layers");
    const auto req=request(156,1);const auto hand=inventory(1182);
    const RichonlineGameFundsSnapshot funds{{1000,2000,50,10},9};
    std::vector<RichonlinePoisonVictim> victims{{0,12,true,false,false,false,funds,2500},
        {1,11,true,false,false,false,funds,2500},{2,10,true,false,false,false,funds,2500},
        {3,17,true,true,false,false,funds,2500},{4,2,true,false,false,true,funds,2500}};
    auto plan=plan_richonline_poison_card(req,context(),hand,0,2500,footprint,victims);
    check(plan.after_use_count==1 && plan.funds.size()==2 && plan.funds[0].after.cash==0 && plan.funds[0].after.deposit==500,"poison immediate damage/self immunity");
    check(plan.funds[1].after.deposit==1000,"second tile attenuates500");
    plan=plan_richonline_poison_card(req,context(),hand,3,2500,footprint,victims);
    check(plan.after_use_count==4 && plan.bankrupt==std::vector<std::uint8_t>({1,2}),"fourth global poison scales1.5/exact bankruptcy");
    check(hand[2].count==2 && victims[1].funds==funds,"poison mutated source");
    victims[1].funds.funds.deposit.reset();rejects([&]{(void)plan_richonline_poison_card(req,context(),hand,0,2500,footprint,victims);});
    auto no_action=context();no_action.can_act=false;rejects([&]{(void)plan_richonline_poison_card(req,no_action,hand,0,2500,footprint,victims);});
}
}
int main(){try{exact_wire();traps();poison();std::cout<<"research card planners passed\n";}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
