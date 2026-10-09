#include "richonline_npc.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* error) { if(!value) throw std::runtime_error(error); }
template<class F> void reject(F fn) {
    try { fn(); } catch(const CodecError&) { return; }
    throw std::runtime_error("invalid_wealth_card_accepted");
}
}
int main(int argc,char** argv) {
    try {
        const std::filesystem::path root=argc>1 ? std::filesystem::path(argv[1]) : std::filesystem::path("../Richonline");
        const auto resources=RichonlineChanceResources::load(root);
        const auto affix=load_richonline_npc_affix(root,0);
        check(affix==5 && load_richonline_npc_affix(root,1)==5,"real_deity_affix_wrong");
        const auto request=decode_richonline_wealth_card(Bytes{130,0,0x34,0x12,2,0});
        check(request.calendar==0x1234 && request.slot==2 && request.bank==0,"wealth_request_decode_wrong");
        RichonlineChanceInventory inventory{}; inventory[2]={1069,2};
        RichonlineActorStatus status; status.possession=3; status.turtle=2; status.timed_bomb=3;
        const auto plan=plan_richonline_wealth_card(0x1234,request,affix,resources,inventory,status);
        check(plan.response40d2==Bytes({0xd2,0x40,0x34,0x12,2,0}),"wealth_attach_wire_wrong");
        check(plan.inventory_before==inventory && plan.inventory_after[2]==RichonlineChanceCardSlot{1069,1},"wealth_card_not_consumed_once");
        auto expected=status; expected.possession=0;
        check(plan.status_after==expected && plan.status_before==status && plan.possession_turns==5,"wealth_attachment_lost_status");
        check(plan.expected_request==34 && plan.money_origin==RichonlineDeityMoneyOrigin::summoned_card,"wealth_roulette_sequence_wrong");
        const std::array<RichonlineGameFundsSnapshot,2> before{{{{100,1000,7,99},4},{{40,100,8,88},9}}};
        const auto money=plan_richonline_deity_money({0x1234,0,plan.money_origin,{10,20}},70,plan.status_after,before);
        check(money.after[0].cash==170 && money.after[1].cash==0 && money.after[1].deposit==70 &&
            money.continuation==RichonlineNpcContinuation::restore_action && !money.expects_ack,"wealth_card_money_cycle_failed");
        inventory[2].count=1;
        const auto last=plan_richonline_wealth_card(1,request,affix,resources,inventory,status);
        check(last.inventory_after[2]==RichonlineChanceCardSlot{},"last_wealth_card_slot_not_cleared");
        reject([&] { plan_richonline_wealth_card(1,request,affix,resources,last.inventory_after,status); });
        reject([&] { plan_richonline_wealth_card(1,request,0,resources,inventory,status); });
        reject([] { decode_richonline_wealth_card(Bytes{130,0,1,0,8,0}); });
        reject([] { decode_richonline_wealth_card(Bytes{130,0,1,0,2,1}); });
        reject([] { decode_richonline_wealth_card(Bytes{131,0,1,0,2,0}); });
        reject([] { parse_richonline_npc_affix("[NPC]\nindx=0\naffix=5\n[NPC]\nindx=0\naffix=5\n",0); });
        reject([] { parse_richonline_npc_affix("[NPC]\nindx=9\naffix=-1\n",9); });
        std::cout<<"NEW wealth card attach, roulette and resource tests passed\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
