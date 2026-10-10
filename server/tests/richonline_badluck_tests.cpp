#include "richonline_npc.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* error) { if(!value) throw std::runtime_error(error); }
template<class F> void reject(F fn) {
    try { fn(); } catch(const CodecError&) { return; }
    throw std::runtime_error("invalid_badluck_plan_accepted");
}
}
int main(int argc,char** argv) {
    try {
        const auto resources=RichonlineChanceResources::load(argc>1 ? argv[1] : "../Richonline");
        const auto names=RichonlineChanceEventTable::load(argc>1 ? argv[1] : "../Richonline");
        check(load_richonline_npc_affix(argc>1 ? argv[1] : "../Richonline",2)==5,"badluck_affix_wrong");
        RichonlineChanceInventory inventory{}; inventory[2]={1038,2}; inventory[7]={1039,1};
        RichonlineActorStatus status; status.possession=2;
        for(const int count:{0,1,2,3,4,8,9}) {
            RichonlineChanceInventory stack{};if(count) stack[2]={1038,static_cast<std::int8_t>(count)};
            std::vector<std::size_t> bounds;
            const auto slots=select_richonline_badluck_half(stack,4,[&](std::size_t bound) {
                bounds.push_back(bound);return bound-1;
            });
            const auto expected=static_cast<std::size_t>(std::min(count/2,4));
            check(bounds.size()==expected,"badluck_did_not_lose_half_units");
            for(std::size_t i=0;i<slots.size();++i)
                check(slots[i]==(i<expected?2:-1),"badluck_half_slots_or_sentinels_wrong");
            const auto half=plan_richonline_badluck(0x1234,RichonlineDeityMoneyOrigin::ground,false,
                slots,resources,stack,status,names);
            check(half.inventory_after[2].count==count-static_cast<int>(expected),"badluck_half_wire_removed_too_many");
            for(std::size_t i=0;i<expected;++i) check(bounds[i]==static_cast<std::size_t>(count)-i,
                "badluck_sampling_replaced_card_unit");
        }
        RichonlineChanceInventory pair{};pair[2]={1038,1};pair[7]={1039,1};
        check(select_richonline_badluck_half(pair,4,[](std::size_t n){return n-1;})==
            std::array<std::int8_t,4>{7,-1,-1,-1},"badluck_two_cards_lost_both");
        check(select_richonline_badluck_half(inventory,0,[](std::size_t){return std::size_t{0};})==
            std::array<std::int8_t,4>{-1,-1,-1,-1},"badluck_zero_limit_ignored");
        reject([&]{select_richonline_badluck_half(pair,4,[](std::size_t n){return n;});});
        reject([&]{select_richonline_badluck_half(pair,5,[](std::size_t){return std::size_t{0};});});
        const auto run=[&](std::array<std::int8_t,4> slots,bool synthetic=false,
            RichonlineDeityMoneyOrigin origin=RichonlineDeityMoneyOrigin::ground) {
            return plan_richonline_badluck(0x1234,origin,synthetic,slots,resources,inventory,status,names);
        };
        const auto plan=run({2,7,-1,-1});
        check(plan.messages==std::vector<Bytes>{{0x24,0x40,0x34,0x12,2,7,255,255}},"badluck_wire_wrong");
        check(plan.inventory_before==inventory && plan.inventory_after[2]==RichonlineChanceCardSlot{1038,1} &&
            plan.inventory_after[7]==RichonlineChanceCardSlot{},"badluck_did_not_decrement_one");
        check(plan.continuation==RichonlineNpcContinuation::landing_phase1 && !plan.expects_ack,"badluck_continuation_wrong");
        check(run({2,2,7,-1}).inventory_after==RichonlineChanceInventory{},"repeated_slot_not_counted");
        check(run({-1,-1,-1,-1}).inventory_after==inventory,"empty_loss_changed_inventory");
        check(run({-1,-1,-1,-1}).messages.front()==Bytes({0x24,0x40,0x34,0x12,255,255,255,255}),"empty_loss_wire_wrong");
        check(run({-1,-1,-1,-1},true).messages.empty(),"synthetic_wait_packet_invented");
        check(run({2,-1,-1,-1},false,RichonlineDeityMoneyOrigin::temple).continuation==RichonlineNpcContinuation::landing_phase6,"temple_phase_wrong");
        check(run({2,-1,-1,-1},false,RichonlineDeityMoneyOrigin::summoned_card).continuation==RichonlineNpcContinuation::restore_action,"summon_action_wrong");
        reject([&]{run({-1,2,-1,-1});}); reject([&]{run({2,2,2,-1});});
        reject([&]{run({8,-1,-1,-1});}); reject([&]{run({0,-1,-1,-1});});
        reject([&]{run({2,-1,-1,-1},true);}); reject([&]{run({-2,-1,-1,-1});});
        status.possession=3; reject([&]{run({2,-1,-1,-1});});
        std::cout<<"NEW badluck slot consumption and continuation tests passed\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
