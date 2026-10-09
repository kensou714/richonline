#include "richonline_deity_card.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool ok,const char* message) {if(!ok) throw std::runtime_error(message);}
template<class F> void rejects(F f,std::string_view reason) {
    try {f();} catch(const CodecError& e) {if(e.what()==reason) return;throw;}
    throw std::runtime_error("expected rejection");
}
void run(const std::filesystem::path& root) {
    auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
    RichonlineBossCards cards(resources,0x1234,{"BS_1_1.emp",17,1038,{0x12,0x34}});
    cards.commit_inventory(cards.prepare_add(1047,2));
    const auto req=parse_richonline_deity_card(Bytes{112,0,3,2,0,0,7,0xef});
    check(req.calendar==0x203 && req.unread7==0xef,"request fields");
    RichonlineDeityCardTarget target{7,true,true,{}};
    target.status.possession=5;target.status.turtle=3;
    RichonlineSummonedNpc npc{321,0,5,true,true};
    const auto before=cards.inventory();
    const auto plan=plan_richonline_deity_card(0x1234,req,0x203,target,npc,cards,7);
    check(plan.response==Bytes{0xc0,0x40,0x34,0x12,0,0,0x41,1,7} &&
        plan.after.status.possession==0 && plan.after.status.turtle==3 &&
        plan.remove_ground_npc==npc && plan.possession_turns==5 &&
        plan.continuation==RichonlineDeityCardContinuation::await_money34 &&
        plan.consumption.remaining_inventory[0]==RichonlineChanceCardSlot{1047,1} && cards.inventory()==before,
        "summon projection/inventory/rules");
    for(const auto id:{1,2,3,4,5,6,7,18}) {
        npc.id=static_cast<std::int8_t>(id);
        const auto p=plan_richonline_deity_card(0x1234,req,0x203,target,npc,cards,7);
        check(p.after.status.possession==id,"wrong attached NPC");
        const auto expected=id==1 ? RichonlineDeityCardContinuation::await_money34 :
            id==2 ? RichonlineDeityCardContinuation::send_lost_cards4024 :
            id==3 ? RichonlineDeityCardContinuation::send_fortune4023 :
            id==7 ? RichonlineDeityCardContinuation::resolve_sleepwalking : RichonlineDeityCardContinuation::restore_action;
        check(p.continuation==expected,"NPC immediate effect omitted");
    }
    npc.id=8;
    const auto other_actor=plan_richonline_deity_card(0x1234,req,0x203,target,
        RichonlineSummonedNpc{321,0,5,true,true},cards,0);
    check(other_actor.after.status.possession==0 && other_actor.continuation==RichonlineDeityCardContinuation::restore_action,
        "summoning_to_other_actor_must_not_request_current_actor_roulette");
    const auto other_sleep=plan_richonline_deity_card(0x1234,req,0x203,target,
        RichonlineSummonedNpc{321,7,3,true,true},cards,0);
    check(other_sleep.continuation==RichonlineDeityCardContinuation::resolve_sleepwalking,
        "other_actor_sleepwalking_requires_protection_resolution");
    rejects([&]{plan_richonline_deity_card(1,req,0x203,target,npc,cards,7);},"richonline_deity_card_ground_npc_invalid");
    npc.id=0;npc.visible=false;
    rejects([&]{plan_richonline_deity_card(1,req,0x203,target,npc,cards,7);},"richonline_deity_card_ground_npc_invalid");
    npc.visible=true;
    rejects([&]{plan_richonline_deity_card(1,req,0,target,npc,cards,7);},"richonline_deity_card_calendar_mismatch");
    target.in_target_selection=false;
    rejects([&]{plan_richonline_deity_card(1,req,0x203,target,npc,cards,7);},"richonline_deity_card_target_invalid");
    target.in_target_selection=true;
    cards.commit_consumption(plan.consumption);
    rejects([&]{cards.commit_consumption(plan.consumption);},"richonline_card_consumption_inventory_changed");
    cards.commit_inventory({});cards.commit_inventory(cards.prepare_add(1048));
    auto dismiss=req;dismiss.kind=RichonlineDeityCard::dismiss1048;
    const auto sent=plan_richonline_deity_card(0x1234,dismiss,0x203,target,std::nullopt,cards,7);
    check(sent.response==Bytes{0xc1,0x40,0x34,0x12,0,0,7} && !sent.after.status.possession &&
        !sent.remove_ground_npc && sent.possession_turns==0 && sent.after.status.turtle==3 &&
        sent.continuation==RichonlineDeityCardContinuation::restore_action,"dismiss state");
    target.status.possession.reset();
    rejects([&]{plan_richonline_deity_card(1,dismiss,0x203,target,std::nullopt,cards,7);},"richonline_deity_card_no_possession");
    rejects([&]{parse_richonline_deity_card(Bytes{112,0,0,0,0,0,8,0});},"richonline_deity_card_fields_invalid");
    rejects([&]{parse_richonline_deity_card(Bytes{112,0,0,0,0,1,0,0});},"richonline_deity_card_fields_invalid");
    rejects([&]{parse_richonline_deity_card(Bytes{112,0,0,0,0,0,0});},"richonline_deity_card_wire_invalid");
}
}
int main(int argc,char** argv) {
    try {if(argc!=2) throw std::runtime_error("resource_path_required");run(argv[1]);
        std::cout<<"PASS NEW summon/dismiss wire, ground selection, inventory CAS, immediate continuations\n";
    } catch(const std::exception& e) {std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}
