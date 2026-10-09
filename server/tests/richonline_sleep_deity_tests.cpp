#include "richonline_npc.hpp"
#include <iostream>
namespace {
using namespace richnet;
void check(bool value,const char* error) { if(!value) throw std::runtime_error(error); }
template<class F> void reject(F fn) { try { fn(); } catch(const CodecError&) { return; } throw std::runtime_error("invalid_sleep_deity_accepted"); }
}
int main(int argc,char** argv) {
    try {
        const auto root=argc>1 ? argv[1] : "../Richonline";
        const auto resources=RichonlineChanceResources::load(root);
        const auto affix=load_richonline_npc_affix(root,7);
        check(affix==3,"sleep_deity_affix_wrong");
        RichonlineChanceInventory inventory{}; inventory[4]={1071,2};
        RichonlineActorStatus status; status.possession=7; status.turtle=2; status.timed_bomb=3;
        const auto run=[&](RichonlineSleepProtection protection) { return plan_richonline_sleep_deity(affix,resources,inventory,status,protection); };
        auto plan=run({false,{}});
        check(plan.status_after==status && plan.inventory_after==inventory && plan.possession_turns==3 && !plan.blocked_by_protection,"sleep_attachment_not_preserved");
        plan=run({true,4}); auto detached=status; detached.possession.reset();
        check(plan.status_after==detached && plan.inventory_after[4]==RichonlineChanceCardSlot{1071,1} &&
            plan.possession_turns==0 && plan.blocked_by_protection && plan.consumed_inventory_slot==4,"automatic_protection_wrong");
        inventory[4].count=1; check(run({true,4}).inventory_after[4]==RichonlineChanceCardSlot{},"last_protection_not_removed");
        status.protected_from_status=true; plan=run({false,{}});
        check(plan.inventory_after==inventory && !plan.status_after.possession && !plan.consumed_inventory_slot,"passive_protection_consumed_card");
        reject([&]{run({true,4});}); status.protected_from_status=false;
        reject([&]{run({true,{}});}); reject([&]{run({false,4});}); reject([&]{run({true,8});}); reject([&]{run({true,0});});
        status.possession=3; reject([&]{run({false,{}});});
        std::cout<<"NEW sleep deity attachment and automatic protection tests passed\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
