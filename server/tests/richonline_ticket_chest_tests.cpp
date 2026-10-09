#include "richonline_npc.hpp"
#include <iostream>
namespace {
using namespace richnet;
void check(bool value,const char* error) { if(!value) throw std::runtime_error(error); }
template<class F> void reject(F fn) { try { fn(); } catch(const CodecError&) { return; } throw std::runtime_error("invalid_chest_accepted"); }
}
int main(int argc,char** argv) {
    try {
        const auto rules=RichonlineTicketChestRules::load(argc>1 ? argv[1] : "../Richonline");
        check(rules.tickets==200,"real_chest_tickets_wrong");
        const RichonlineGameFundsSnapshot funds{{100,1000,7,99},4};
        RichonlineActorStatus status;
        const auto plan=plan_richonline_ticket_chest(rules,false,status,funds);
        check(plan.before==funds && plan.after.tickets==207 && plan.after.cash==100 && plan.after.deposit==1000 && plan.after.reserve==99,
            "chest_balance_projection_wrong");
        check(plan.remove_ground_npc && !plan.expects_ack && plan.continuation==RichonlineNpcContinuation::landing_phase1,"chest_continuation_wrong");
        const auto boss=plan_richonline_ticket_chest(rules,true,status,funds);
        check(boss.remove_ground_npc && boss.after==funds.funds,"synthetic_chest_reward_invented");
        status.possession=7;
        check(!plan_richonline_ticket_chest(rules,false,status,funds).remove_ground_npc,"sleeping_actor_removed_chest");
        status.possession.reset(); status.sleepwalking=1;
        check(plan_richonline_ticket_chest(rules,false,status,funds).after==funds.funds,"sleepwalking_actor_got_tickets");
        status.sleepwalking=0; status.frozen=1;
        check(plan_richonline_ticket_chest(rules,false,status,funds).remove_ground_npc,"invented_frozen_ground_guard");
        status.frozen=0;
        auto boundary=funds; boundary.funds.tickets=2147483447U;
        check(plan_richonline_ticket_chest(rules,false,status,boundary).after.tickets==2147483647U,"chest_signed_boundary_wrong");
        ++boundary.funds.tickets; reject([&]{plan_richonline_ticket_chest(rules,false,status,boundary);});
        reject([]{RichonlineTicketChestRules::parse("[ITEM]\nindx=14\nvalue=32768\n");});
        reject([]{RichonlineTicketChestRules::parse("[ITEM]\nindx=13\nvalue=200\n");});
        reject([]{RichonlineTicketChestRules::parse("[ITEM]\nindx=14\nvalue=200\n[ITEM]\nindx=14\nvalue=300\n");});
        std::cout<<"NEW chest resource, local credit and continuation tests passed\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
