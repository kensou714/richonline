#include "richonline_npc.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool ok,const char* reason) { if(!ok) throw std::runtime_error(reason); }
template<class F> void rejected(F fn) {
    try { fn(); } catch(const CodecError&) { return; }
    throw std::runtime_error("invalid_npc_plan_accepted");
}
void fortune_paths(const std::filesystem::path& root) {
    const auto resources=RichonlineChanceResources::load(root);
    const auto names=RichonlineChanceEventTable::load(root);
    const auto rules=RichonlineNpcRules::load(root);
    check(rules.fortune_affix_turns==5,"real_npc_affix_not_loaded");
    const RichonlineGameFundsSnapshot funds{{12345,6789,120,300},7};
    RichonlineActorStatus status; status.possession=1; status.turtle=2; status.timed_bomb=3;
    RichonlineChanceInventory inventory{};
    for(const auto origin:{RichonlineNpcOrigin::ground,RichonlineNpcOrigin::temple,RichonlineNpcOrigin::fortune_card1070}) {
        auto initial=inventory;
        RichonlineFortuneContext ctx{0x1234,0,231,false,origin,{}};
        if(origin==RichonlineNpcOrigin::fortune_card1070) {
            initial[0]={1070,1}; ctx.card=decode_richonline_fortune_card(Bytes{131,0,7,0,0,0});
        }
        const auto plan=plan_richonline_fortune(ctx,rules,resources,names,"BS_1_1.emp",{1038,1044},initial,status,funds);
        check(plan.messages.back()==Bytes({0x23,0x40,0x34,0x12,0x0e,4,0x14,4}),"fortune_reward_wire_wrong");
        check(!plan.expects_ack && plan.inventory_before==initial && plan.status_before==status &&
            plan.funds_before==funds && plan.funds_after==funds.funds,"fortune_mutated_snapshot_or_money");
        check(plan.inventory_after[0]==RichonlineChanceCardSlot{1038,1} &&
            plan.inventory_after[1]==RichonlineChanceCardSlot{1044,1},"fortune_did_not_add_both_cards");
        auto expected_status=status; expected_status.possession=3;
        check(plan.status_after==expected_status && plan.possession_turns==5,"fortune_lost_unrelated_status");
        if(origin==RichonlineNpcOrigin::ground) {
            check(plan.messages.size()==2 && plan.messages.front()==Bytes({0x13,0x40,0x34,0x12,231,0}) &&
                plan.remove_ground_npc && plan.continuation==RichonlineNpcContinuation::landing_phase1,"ground_fortune_phase_wrong");
        } else if(origin==RichonlineNpcOrigin::temple) {
            check(plan.messages.size()==1 && !plan.remove_ground_npc &&
                plan.continuation==RichonlineNpcContinuation::landing_phase6,"temple_fortune_repeated_stop_or_wrong_phase");
        } else check(plan.messages.size()==2 && plan.messages.front()==Bytes({0xd3,0x40,0x34,0x12,0,0}) &&
            plan.continuation==RichonlineNpcContinuation::restore_action,"card_fortune_did_not_restore_action");
    }
    RichonlineFortuneContext ground{0x1234,0,231,false,RichonlineNpcOrigin::ground,{}};
    const std::array<std::int16_t,8> ids{1038,1039,1040,1041,1042,1043,1044,1045};
    for(std::size_t i=0;i<ids.size();++i) inventory[i]={ids[i],1};
    const auto full=plan_richonline_fortune(ground,rules,resources,names,"BS_1_1.emp",{1046,1038},inventory,status,funds);
    check(full.inventory_after==inventory && full.messages.size()==2 && !full.expects_ack,
        "full_bag_changed_inventory_or_stalled_phase");
    ground.synthetic=true; ground.actor=1;
    const auto boss=plan_richonline_fortune(ground,rules,resources,names,"BS_1_1.emp",{1038,1044},inventory,status,funds);
    check(boss.messages.size()==1 && boss.inventory_after==inventory && boss.status_after.possession==3 &&
        boss.continuation==RichonlineNpcContinuation::landing_phase1,"synthetic_boss_incorrectly_waited_for_gift");
    ground.synthetic=false;
    rejected([&] { plan_richonline_fortune(ground,rules,resources,names,"BS_1_1.emp",{-1,1044},inventory,status,funds); });
    ground.origin=RichonlineNpcOrigin::fortune_card1070; ground.card=RichonlineFortuneCardRequest{7,0,0};
    rejected([&] { plan_richonline_fortune(ground,rules,resources,names,"BS_1_1.emp",{1038,1044},inventory,status,funds); });
    rejected([] { decode_richonline_fortune_card(Bytes{131,0,7,0,8,0}); });
    rejected([] { decode_richonline_fortune_card(Bytes{131,0,7,0,0,1}); });
    rejected([] { RichonlineNpcRules::parse("[NPC]\nindx=3\naffix=0\n"); });
    rejected([] { RichonlineNpcRules::parse("[NPC]\nindx=3\naffix=5\n[NPC]\nindx=3\naffix=5\n"); });
}
void wealth_and_poverty_money() {
    check(decode_richonline_deity_roulette(Bytes{34,0,0x34,0x12,1,0xcd}).calendar==0x1234,
        "roulette_request_calendar_wrong");
    check(decode_richonline_deity_roulette(Bytes{34,0,7,0,1,0xcd}).unread5==0xcd,
        "roulette_unread_byte_treated_as_zero");
    rejected([] { decode_richonline_deity_roulette(Bytes{34,0,7,0,0,0}); });
    const std::array<RichonlineGameFundsSnapshot,2> before{{{{100,1000,7,99},4},{{40,100,8,88},9}}};
    RichonlineActorStatus status; status.possession=0;
    RichonlineDeityMoneyContext ctx{0x1234,0,RichonlineDeityMoneyOrigin::summoned_card,{10,20}};
    const auto result=plan_richonline_deity_money(ctx,70,status,before);
    check(result.response4022==Bytes({0x22,0x40,0x34,0x12,70,0,0}) && !result.expects_ack &&
        !result.awaits_settlement && !result.bankrupt_actor && result.continuation==RichonlineNpcContinuation::restore_action,
        "wealth_response_or_continuation_wrong");
    check(result.before==before && result.after[0]==RichonlineGameFunds{170,1000,7,99} &&
        result.after[1]==RichonlineGameFunds{0,70,8,88},"wealth_cash_then_deposit_wrong");
    const auto exact=plan_richonline_deity_money(ctx,140,status,before);
    check(exact.awaits_settlement && exact.bankrupt_actor==1 && exact.response4022.back()==1 &&
        exact.after[0].cash==240 && exact.after[1].cash==0 && exact.after[1].deposit==0,
        "wealth_exact_exhaustion_did_not_wait_for_settlement");
    const auto over=plan_richonline_deity_money(ctx,150,status,before);
    check(over.after[0].cash==250 && over.after[1].deposit==0 && over.awaits_settlement,
        "wealth_did_not_mirror_client_full_credit_and_clamped_debit");
    status.possession=1; ctx.origin=RichonlineDeityMoneyOrigin::ground;
    const auto poverty=plan_richonline_deity_money(ctx,150,status,before);
    check(poverty.after[0]==RichonlineGameFunds{0,950,7,99} && poverty.after[1]==RichonlineGameFunds{190,100,8,88} &&
        poverty.continuation==RichonlineNpcContinuation::landing_phase1,"poverty_direction_wrong");
    ctx.origin=RichonlineDeityMoneyOrigin::temple;
    const auto temple=plan_richonline_deity_money(ctx,0,status,before);
    check(temple.after==std::array{before[0].funds,before[1].funds} &&
        temple.continuation==RichonlineNpcContinuation::landing_phase6,"zero_result_or_temple_phase_wrong");
    status.possession=0; ctx.actor44={1,1};
    rejected([&] { plan_richonline_deity_money(ctx,10,status,before); });
    ctx.actor44={1,2};
    auto unknown=before; unknown[1].funds.deposit.reset();
    rejected([&] { plan_richonline_deity_money(ctx,10,status,unknown); });
    auto overflow=before; overflow[0].funds.cash=2147483647;
    rejected([&] { plan_richonline_deity_money(ctx,1,status,overflow); });
    overflow=before; overflow[0].funds.cash=2147483600; overflow[0].funds.deposit=48;
    rejected([&] { plan_richonline_deity_money(ctx,0,status,overflow); });
    overflow[0].funds.deposit=40;
    rejected([&] { plan_richonline_deity_money(ctx,8,status,overflow); });
    const auto boundary=plan_richonline_deity_money(ctx,7,status,overflow);
    check(boundary.after[0].cash+*boundary.after[0].deposit==2147483647U,"money_total_boundary_failed");
    status.possession=3;
    rejected([&] { plan_richonline_deity_money(ctx,10,status,before); });
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_path_required"); fortune_paths(std::filesystem::path(argv[1])); wealth_and_poverty_money();
        std::cout << "PASS NEW fortune NPC two-card reward, origin phases, synthetic bypass and full inventory\n";
    } catch(const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
