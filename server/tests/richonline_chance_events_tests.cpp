#include "richonline_chance_events.hpp"
#include "richonline_actor_status.hpp"
#include <iostream>
#include <limits>
namespace {
using namespace richnet;
void check(bool condition,std::string_view message) { if(!condition) throw std::runtime_error(std::string(message)); }
template<class F> void rejects(F call) { try {call();} catch(const CodecError&) {return;} throw std::runtime_error("expected rejection"); }
void money(const std::filesystem::path& root) {
    const auto table=RichonlineChanceEventTable::load(root);
    check(table.size("V_BS_1_1.emp")==34 && table.size("BS_1_1.emp")==50,"map indexes");
    check(table.event("V_BS_1_1.emp",17).category==0 && table.event("BS_1_1.emp",17).category==5,"map collision");
    const auto gain=plan_richonline_chance_money(table,"V_BS_1_1.emp",13,0xabcd,2000,{12000,4000},{0xa5,0x5a});
    check(gain.after==RichonlineChanceMoneyState{14000,4000} && gain.client_continues_phase2 && !gain.insolvent,"fixed gain");
    check(gain.packet==Bytes{0x96,0x40,0xcd,0xab,13,0,0xa5,0x5a,0xd0,7,0,0},"wire and opaque");
    const auto loss=plan_richonline_chance_money(table,"V_BS_1_1.emp",17,1,2000,{1000,4000},{1,2});
    check(loss.after==RichonlineChanceMoneyState{0,3000} && loss.client_continues_phase2,"cash then deposit");
    const auto bankrupt=plan_richonline_chance_money(table,"V_BS_1_1.emp",17,1,2000,{1000,1000},{1,2});
    check(bankrupt.after==RichonlineChanceMoneyState{0,0} && !bankrupt.client_continues_phase2 && bankrupt.insolvent,"exact exhaustion");
    const auto pct=plan_richonline_chance_money(table,"V_BS_1_1.emp",1,1,10,{101,4000},{1,2});
    check(pct.after==RichonlineChanceMoneyState{91,4000},"percent only cash truncates");
    rejects([&]{plan_richonline_chance_money(table,"V_BS_1_1.emp",1,1,9,{100,0},{1,2});});
    rejects([&]{plan_richonline_chance_money(table,"V_BS_1_1.emp",1,1,15,{200000000,0},{1,2});});
    rejects([&]{plan_richonline_chance_money(table,"V_BS_1_1.emp",13,1,2000,{std::numeric_limits<std::int32_t>::max(),0},{1,2});});
    rejects([&]{table.event("V_BS_1_1.emp",34);});
    rejects([&]{table.event("V_BS_1_1.emp",-1);});
}
void cards(const std::filesystem::path& root) {
    const auto table=RichonlineChanceEventTable::load(root); const auto resources=RichonlineChanceResources::load(root);
    RichonlineChanceInventory empty{};
    const std::array<std::int32_t,1> controlled{1038};
    const auto one=plan_richonline_chance_cards(table,resources,"V_BS_1_1.emp",2,77,controlled,empty,{1,2});
    check(one.after[0]==RichonlineChanceCardSlot{1038,1} && one.packet.size()==12,"single grant");
    const auto many=plan_richonline_chance_cards(table,resources,"V_BS_1_1.emp",16,77,controlled,empty,{1,2});
    check(many.after==one.after && many.packet.size()==16 && read_le(View(many.packet).subspan(8,4))==1,"multiple layout");
    auto full=empty; full.fill({1038,1});
    const auto overflow=plan_richonline_chance_cards(table,resources,"V_BS_1_1.emp",2,77,controlled,full,{1,2});
    check(overflow.after==full && overflow.packet.size()==12,"full inventory completes");
    auto stacked=empty; stacked[3]={1038,2}; const std::array<std::int32_t,1> slot{3};
    const auto removed=plan_richonline_chance_cards(table,resources,"V_BS_1_1.emp",18,77,slot,stacked,{1,2});
    check(removed.after[3]==RichonlineChanceCardSlot{1038,1},"remove one not whole slot");
    const auto last=plan_richonline_chance_cards(table,resources,"V_BS_1_1.emp",18,77,slot,removed.after,{1,2});
    check(last.after[3]==RichonlineChanceCardSlot{},"last removal clears");
    const std::array<std::int32_t,2> duplicate{3,3};
    rejects([&]{plan_richonline_chance_cards(table,resources,"V_BS_1_1.emp",20,77,duplicate,stacked,{1,2});});
    rejects([&]{plan_richonline_chance_cards(table,resources,"V_BS_1_1.emp",18,77,slot,empty,{1,2});});
    const std::array<std::int32_t,1> wrong{1044};
    rejects([&]{plan_richonline_chance_cards(table,resources,"V_BS_1_1.emp",2,77,wrong,empty,{1,2});});
}
void malicious() {
    rejects([]{RichonlineChanceEventTable::parse("map\t17\t0\t0\t0\t0\t0\t,\ti\tt");});
    const auto table=RichonlineChanceEventTable::parse("map\t2\t0\t0\t0\t1\t1\t,\ti\t%n");
    rejects([&]{plan_richonline_chance_money(table,"map",0,0,1,{0,0},{1,2});});
    const auto long_name=RichonlineChanceEventTable::parse("map\t4\t0\t0\t0\t2\t2\t,\ti\t%d",
        "[PROP]\nindx=7\nname="+std::string(70,'x'),"[ITEM]\nindx=24\nstring=gain\n[ITEM]\nindx=154\nstring=full");
    const std::array<std::int16_t,2> names{7,7};
    rejects([&]{long_name.card_panel_bytes(names,false,false);});
}
void statuses(const std::filesystem::path& root) {
    const auto table=RichonlineChanceEventTable::load(root); const auto rules=RichonlineStatusRules::load(root);
    RichonlineActorStatus state; state.six_steps=2;
    const auto one=plan_richonline_chance_status(table,"V_BS_1_1.emp",22,1,{},state,rules,{false,{}},{1,2});
    check(one.packet.size()==6 && one.after.one_step==rules.fixed_step_turns+1 && one.after.six_steps==0,"one-step replacement");
    auto previous=one.after; richonline_status_finish_previous_turn(previous);
    check(previous.one_step==rules.fixed_step_turns,"applied-turn compensation");
    const std::array<std::int32_t,1> sleepdays{2};
    const auto sleep=plan_richonline_chance_status(table,"V_BS_1_1.emp",27,1,sleepdays,{},rules,{false,{}},{1,2});
    check(sleep.after.sleepwalking==3 && sleep.packet.size()==12,"sleep duration");
    const auto guard=plan_richonline_chance_status(table,"V_BS_1_1.emp",27,1,sleepdays,{},rules,{true,3},{1,2});
    check(guard.after.sleepwalking==0 && guard.blocked_by_protection && guard.consumed_inventory_slot==3,"card1071 immunity");
    RichonlineActorStatus protected_actor; protected_actor.protected_from_status=true;
    const auto god=plan_richonline_chance_status(table,"V_BS_1_1.emp",27,1,sleepdays,protected_actor,rules,{true,3},{1,2});
    check(!god.consumed_inventory_slot && god.after.sleepwalking==0,"protection precedes card consumption");
    const std::array<std::int32_t,2> buff{30,3};
    const auto attack=plan_richonline_chance_status(table,"V_BS_1_1.emp",8,1,buff,protected_actor,rules,{false,{}},{1,2});
    check(attack.after.attack_multiplier==1.3F && attack.after.attack_turns==3 && !attack.blocked_by_protection && attack.packet.size()==16,"buff not blocked");
    auto stage=attack.after; stage.frozen=3; stage.sleepwalking=3;
    richonline_status_begin_active_turn(stage); check(stage.frozen==2 && stage.sleepwalking==3 && stage.attack_turns==3,"active hook only freeze");
    richonline_status_begin_combat_phase(stage); check(stage.attack_turns==2,"combat hook");
    const auto recover_table=RichonlineChanceEventTable::parse("map\t16\t0\t0\t0\t0\t0\t,\ti\trecovered");
    stage.possession=7; stage.timed_bomb=3;
    const auto recovered=plan_richonline_chance_status(recover_table,"map",0,1,{},stage,rules,{false,{}},{1,2});
    check(recovered.detached_possession && recovered.removed_timed_bomb && !recovered.after.possession &&
        !recovered.after.timed_bomb && recovered.after.frozen==2,"recovery affects god and bomb only");
    const std::array<std::int32_t,2> bad{30,259};
    rejects([&]{plan_richonline_chance_status(table,"V_BS_1_1.emp",8,1,bad,{},rules,{false,{}},{1,2});});
}
}
int main(int argc,char** argv) {
    try { if(argc!=2) throw std::runtime_error("expected NEW root"); money(argv[1]); cards(argv[1]); statuses(argv[1]); malicious();
        std::cout<<"PASS NEW chance category 0..16 planning, resource bounds, money, inventory, status and presentation\n";
    } catch(const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
