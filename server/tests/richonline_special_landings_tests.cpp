#include "richonline_special_landings.hpp"
#include <iostream>
#include <limits>
namespace {
using namespace richnet;
void check(bool condition,const char* reason) {if(!condition) throw std::runtime_error(reason);}
template<class F> void rejects(F f) {try {f();} catch(const CodecError&) {return;} throw std::runtime_error("expected_rejection");}
RichonlineSpecialLandingContext context(std::int8_t type=57,std::uint8_t actor=0) {
    return {{actor,114,type,-1,3,actor==1,2,false,{}},false};
}
RichonlineGameLedger ledger(std::uint32_t tickets=25,std::uint32_t cash=10) {
    return RichonlineGameLedger(std::vector<RichonlineGameFunds>{{cash,30,tickets,40},{50,60,0,70}});
}
void merchant() {
    auto funds=ledger();const auto before=funds.snapshot(0);auto cell=context();
    auto plan=prepare_richonline_special_landing(0x1234,cell,before);
    check(plan && plan->outcome()==RichonlineSpecialOutcome::merchant_exchange &&
        plan->continuation()==RichonlineSpecialContinuation::property_phase2 && !plan->expects_client_request(),"merchant_continuation");
    check(plan->messages()==std::vector<Bytes>{{0x13,0x40,0x34,0x12,114,0}},"merchant_duplicate_funds_packet");
    check(funds.snapshot(0)==before && plan->after()==RichonlineGameFunds{2010,30,0,40},"merchant_wrong_sign_or_amount");
    auto copy=*plan;
    check(commit_richonline_special_landing(funds,*plan,cell.landing.actor_status,[]{return true;}),"merchant_commit");
    check(!commit_richonline_special_landing(funds,*plan,cell.landing.actor_status,[]{return true;}),"merchant_repeat");
    rejects([&]{commit_richonline_special_landing(funds,copy,cell.landing.actor_status,[]{return true;});});
    auto low=ledger(24);auto refused=prepare_richonline_special_landing(1,cell,low.snapshot(0));
    check(refused && refused->outcome()==RichonlineSpecialOutcome::insufficient_tickets &&
        refused->after()==low.snapshot(0).funds,"insufficient_ticket_mutation");
    auto empty_cash=ledger(26,0);auto zero=prepare_richonline_special_landing(1,cell,empty_cash.snapshot(0));
    check(zero && zero->after()==RichonlineGameFunds{2000,30,1,40} &&
        zero->continuation()==RichonlineSpecialContinuation::property_phase2 && !zero->expects_client_request(),
        "zero_cash_exchange_invented_bankruptcy_wait");
    auto synthetic=context(57,1);auto boss=prepare_richonline_special_landing(1,synthetic,funds.snapshot(1));
    check(boss && boss->after()==RichonlineGameFunds{2050,60,0,70},"boss_should_not_pay_tickets");
}
void controls_and_event_wait() {
    auto funds=ledger();
    for(const auto type:{std::int8_t{57},std::int8_t{58}}) for(int condition=0;condition<4;++condition) {
        auto cell=context(type);
        if(condition==0) cell.landing.actor_status.possession=7;
        else if(condition==1) cell.landing.actor_status.sleepwalking=2;
        else if(condition==2) cell.landing.actor_status.frozen=2;
        else cell.scripted_event_active=true;
        const auto plan=prepare_richonline_special_landing(1,cell,funds.snapshot(0));
        check(plan && plan->continuation()==RichonlineSpecialContinuation::property_phase2 &&
            plan->after()==funds.snapshot(0).funds,"controlled_event_not_skipped");
    }
    for(std::uint8_t actor=0;actor<2;++actor) {
        auto cell=context(58,actor);const auto before=funds.snapshot(actor);
        auto plan=prepare_richonline_special_landing(1,cell,before);
        check(plan && plan->outcome()==RichonlineSpecialOutcome::server_event_required &&
            plan->continuation()==RichonlineSpecialContinuation::awaiting_server_event &&
            !plan->expects_client_request(),"58_must_not_wait_for_client_or_finish");
        rejects([&]{commit_richonline_special_landing(funds,*plan,cell.landing.actor_status,[]{return true;});});
        check(funds.snapshot(actor)==before,"58_wait_changed_funds");
    }
}
void failures() {
    auto funds=ledger();auto cell=context();auto plan=prepare_richonline_special_landing(1,cell,funds.snapshot(0));
    const auto before=funds.snapshot(0);auto stale=cell.landing.actor_status;stale.turtle=2;
    check(!commit_richonline_special_landing(funds,*plan,stale,[]{return true;}) && funds.snapshot(0)==before,"stale_status_commit");
    check(!commit_richonline_special_landing(funds,*plan,cell.landing.actor_status,[]{return false;}) &&
        funds.snapshot(0)==before,"rejected_authority_mutated_funds");
    rejects([&]{commit_richonline_special_landing(funds,*plan,cell.landing.actor_status,[]{throw CodecError("effect_failed");return true;});});
    check(funds.snapshot(0)==before,"failed_transaction_mutated_funds");
    auto invalid=context();invalid.landing.property_ref=3;
    rejects([&]{prepare_richonline_special_landing(1,invalid,before);});
    invalid=context();invalid.landing.game_mode=4;
    rejects([&]{prepare_richonline_special_landing(1,invalid,before);});
    check(!prepare_richonline_special_landing(1,context(5),before),"unrelated_static_claimed");
    const auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    auto overflow=before;overflow.funds.cash=maximum-1999;overflow.funds.deposit=0;
    rejects([&]{prepare_richonline_special_landing(1,cell,overflow);});
    overflow.funds.cash=maximum-2000;overflow.funds.deposit=1;
    rejects([&]{prepare_richonline_special_landing(1,cell,overflow);});
    overflow.funds.deposit=0;check(prepare_richonline_special_landing(1,cell,overflow)->after().cash==maximum,"exact_cash_ceiling");
}
}
int main() {
    try {merchant();controls_and_event_wait();failures();
        std::cout<<"PASS NEW57 local exchange,58 server wait,controlled bypass and atomic ledger boundaries\n";
    } catch(const std::exception& e) {std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}
