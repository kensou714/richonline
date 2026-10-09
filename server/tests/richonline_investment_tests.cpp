#include "richonline_investment.hpp"
#include <iostream>
#include <limits>

namespace {
using namespace richnet;
constexpr std::uint16_t game=0x1234,calendar=0x4567;
constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
void check(bool ok,const char* message) { if(!ok) throw std::runtime_error(message); }
template<class F> void rejects(F action,const char* code) {
    try { action(); } catch(const CodecError& e) { check(std::string(e.what())==code,e.what()); return; }
    throw std::runtime_error("expected_investment_rejection");
}
Bytes decision(bool accept) { return {0x2b,0,0x67,0x45,static_cast<std::uint8_t>(accept),0xcc}; }
struct Fixture {
    RichonlineInvestment::Clock::time_point now{};
    std::shared_ptr<RichonlineGameLedger> ledger=std::make_shared<RichonlineGameLedger>(
        std::vector<RichonlineGameFunds>{{700,300,91,37},{700,300,92,38}});
    RichonlineInvestment investment{game,{100,500,{173,189}},ledger,0xa5,[this]{return now;}};
    RichonlineInvestmentEntry entry{0,173,calendar,RichonlineInvestmentVisit::passing,false,true};
};
void exact_requests_preserve_the_unknown_byte() {
    const auto pass=decode_richonline_investment_pass(Bytes{0x2a,0,0x67,0x45,173,0});
    check(pass.calendar_counter==calendar && pass.position==173,"investment_pass_field_wrong");
    const auto choice=decode_richonline_investment_request(decision(true));
    check(choice.calendar_counter==calendar && choice.accept && choice.unassigned5==0xcc,"investment_request_field_wrong");
    check(!decode_richonline_investment_request(decision(false)).accept,"investment_decline_not_decoded");
    for(std::size_t size=0;size<9;++size) if(size!=6) {
        auto plain=decision(true); plain.resize(size);
        rejects([&]{decode_richonline_investment_request(plain);},"richonline_investment_request_size");
        rejects([&]{decode_richonline_investment_pass(plain);},"richonline_investment_pass_size");
    }
    auto plain=decision(true); plain[0]=0x27;
    rejects([&]{decode_richonline_investment_request(plain);},"richonline_investment_request_opcode");
    rejects([&]{decode_richonline_investment_pass(plain);},"richonline_investment_pass_opcode");
    plain=decision(true); plain[4]=2;
    rejects([&]{decode_richonline_investment_request(plain);},"richonline_investment_decision_invalid");
    rejects([&]{decode_richonline_investment_pass(Bytes{0x2a,0,0x67,0x45,0xff,0xff});},"richonline_investment_position_invalid");
}
void admission_and_completion_keep_original_route() {
    for(const auto visit:{RichonlineInvestmentVisit::passing,RichonlineInvestmentVisit::landing})
    for(const bool accept:{false,true}) {
        Fixture f; f.entry.visit=visit;
        const auto before=f.ledger->snapshot(0);
        const auto opening=f.investment.begin(f.entry);
        check(opening.messages==std::vector<Bytes>{{0x12,0x40,0x34,0x12,173,0,
            static_cast<std::uint8_t>(visit==RichonlineInvestmentVisit::passing),0xa5}},"investment_admission_wire_wrong");
        check(opening.continuation==RichonlineInvestmentContinuation::await_choice && f.investment.active() &&
            opening.funds_after==before && f.investment.state(0).revision==0,"investment_open_changed_assets");
        const auto completed=f.investment.handle(decision(accept));
        check(completed.messages==std::vector<Bytes>{{0x40,0x40,0x34,0x12,static_cast<std::uint8_t>(accept)}},
            "investment_completion_wire_wrong");
        check(completed.continuation==(visit==RichonlineInvestmentVisit::passing ?
            RichonlineInvestmentContinuation::resume_movement : RichonlineInvestmentContinuation::continue_landing),
            "investment_continuation_wrong");
        check(completed.funds_after.funds.cash==(accept ? 600U : 700U) && completed.funds_after.funds.deposit==300 &&
            completed.funds_after.funds.tickets==91 && completed.funds_after.funds.reserve==37 &&
            completed.funds_before==before,"investment_cost_or_unrelated_funds_wrong");
        check(f.investment.state(0).collected[0]==accept && !f.investment.state(0).collected[1] &&
            f.investment.state(0).revision==static_cast<std::uint64_t>(accept),"investment_collection_wrong");
        check(!f.investment.active() && !f.investment.poll(),"investment_completed_twice");
        rejects([&]{f.investment.handle(decision(accept));},"richonline_investment_not_pending");
    }
}
void complete_collection_pays_only_on_a_later_visit() {
    for(const auto visit:{RichonlineInvestmentVisit::passing,RichonlineInvestmentVisit::landing}) {
        Fixture f; f.entry.visit=visit;
        f.investment.begin(f.entry); f.investment.handle(decision(true));
        const auto repeated=f.investment.begin(f.entry);
        check(repeated.messages.empty() && repeated.outcome==RichonlineInvestmentOutcome::already_collected &&
            repeated.funds_after.funds.cash==600,"investment_repeated_point_charged_or_opened");
        f.entry.position=189;
        f.investment.begin(f.entry); const auto last=f.investment.handle(decision(true));
        check(last.funds_after.funds.cash==500 && last.after.collected[0] && last.after.collected[1] &&
            last.outcome==RichonlineInvestmentOutcome::purchased,"investment_reward_was_paid_on_last_purchase");
        // NEW automatically applies investReturn during the next67 handler.
        // There must be no second funds message and no immediately reopened UI.
        const auto reward=f.investment.begin(f.entry);
        check(reward.messages.empty() && reward.outcome==RichonlineInvestmentOutcome::collection_reward &&
            reward.funds_after.funds.cash==1000 && reward.funds_after.funds.deposit==300 &&
            !reward.after.collected[0] && !reward.after.collected[1] && reward.after.revision==3,
            "investment_reward_or_reset_wrong");
        check(reward.continuation==(visit==RichonlineInvestmentVisit::passing ?
            RichonlineInvestmentContinuation::continue_movement : RichonlineInvestmentContinuation::continue_landing),
            "automatic_investment_reward_paused_or_resumed_route");
        const auto again=f.investment.begin(f.entry);
        check(again.outcome==RichonlineInvestmentOutcome::opened,"investment_new_collection_not_opened");
        f.investment.handle(decision(false));
    }
}
void actors_have_independent_collections_and_cash() {
    Fixture f;
    f.investment.begin(f.entry); f.investment.handle(decision(true));
    f.entry.actor_slot=1; const auto opening=f.investment.begin(f.entry);
    check(opening.outcome==RichonlineInvestmentOutcome::opened && !opening.before.collected[0],
        "investment_other_actor_inherited_mark");
    f.investment.handle(decision(true));
    check(f.ledger->snapshot(0).funds.cash==600 && f.ledger->snapshot(1).funds.cash==600 &&
        f.investment.state(0).collected[0] && f.investment.state(1).collected[0],"investment_wrong_actor_cost");
}
void exact_threshold_and_static_guards_do_not_open_ui() {
    for(const auto cash:{0U,99U,100U,101U}) {
        Fixture f; auto funds=f.ledger->snapshot(0); auto changed=funds.funds; changed.cash=cash;
        f.ledger->commit(0,funds,changed); const auto result=f.investment.begin(f.entry);
        if(cash>100) {
            check(result.outcome==RichonlineInvestmentOutcome::opened,"investment_strict_threshold_too_high");
            f.investment.handle(decision(true)); check(f.ledger->snapshot(0).funds.cash==1,"investment_cost_wrong");
        } else check(result.outcome==RichonlineInvestmentOutcome::insufficient_cash && result.messages.empty() &&
            !f.investment.active(),"investment_allowed_cash_equal_to_base_or_bank_spill");
    }
    Fixture f; f.entry.client_static_effect_allowed=false;
    const auto result=f.investment.begin(f.entry);
    check(result.outcome==RichonlineInvestmentOutcome::static_effect_skipped && result.messages.empty() &&
        result.before==result.after && result.funds_before==result.funds_after && !f.investment.active(),
        "investment_ignored_static_event_guard");
}
void deterministic_timeout_and_synthetic_completion() {
    for(const bool late_request:{false,true}) {
        Fixture f; f.investment.begin(f.entry); f.now+=std::chrono::milliseconds{7999};
        check(!f.investment.poll(),"investment_timeout_early"); f.now+=std::chrono::milliseconds{1};
        const auto result=late_request ? f.investment.handle(decision(true)) : *f.investment.poll();
        check(result.outcome==RichonlineInvestmentOutcome::timed_out && result.messages[0][4]==0 &&
            result.funds_after.funds.cash==700 && !f.investment.state(0).collected[0] && !f.investment.active(),
            "investment_timeout_accepted_late_click_or_waited");
    }
    for(const auto visit:{RichonlineInvestmentVisit::passing,RichonlineInvestmentVisit::landing}) {
        Fixture f; f.entry.actor_slot=1; f.entry.synthetic_actor=true; f.entry.visit=visit;
        const auto result=f.investment.begin(f.entry);
        check(result.outcome==RichonlineInvestmentOutcome::synthetic_decline && result.messages.size()==2 &&
            result.messages[0][0]==0x12 && result.messages[1]==Bytes{0x40,0x40,0x34,0x12,0} &&
            result.messages[0][6]==static_cast<std::uint8_t>(visit==RichonlineInvestmentVisit::passing) &&
            !f.investment.active() && result.funds_before==result.funds_after,
            "investment_synthetic_waited_or_skipped_flag_sync");
    }
}
void malformed_and_stale_inputs_preserve_pending_state() {
    Fixture f; f.investment.begin(f.entry);
    rejects([&]{f.investment.begin(f.entry);},"richonline_investment_already_pending");
    auto stale=decision(true); stale[2]=0x66;
    rejects([&]{f.investment.handle(stale);},"richonline_investment_counter_mismatch");
    rejects([&]{f.investment.handle(Bytes{0x2b,0});},"richonline_investment_request_size");
    check(f.investment.active() && f.ledger->snapshot(0).funds.cash==700 && !f.investment.state(0).collected[0],
        "investment_invalid_choice_consumed_pending");
    f.investment.handle(decision(false));
    f.entry.position=-1;
    rejects([&]{f.investment.begin(f.entry);},"richonline_investment_position_invalid");
    f.entry.position=174;
    rejects([&]{f.investment.begin(f.entry);},"richonline_investment_position_invalid");
    f.entry.position=173; f.entry.actor_slot=2;
    rejects([&]{f.investment.begin(f.entry);},"richonline_investment_actor_invalid");
    rejects([&]{f.investment.state(8);},"richonline_investment_actor_invalid");
    f.entry.actor_slot=0; f.entry.visit=static_cast<RichonlineInvestmentVisit>(19);
    rejects([&]{f.investment.begin(f.entry);},"richonline_investment_visit_invalid");
    check(!f.investment.active(),"investment_invalid_entry_opened_ui");
}
void changed_shared_ledger_cannot_charge_or_collect() {
    Fixture f; f.investment.begin(f.entry);
    const auto before=f.ledger->snapshot(0); f.ledger->adjust(0,before,{1,0,0,0});
    rejects([&]{f.investment.handle(decision(true));},"richonline_investment_funds_changed");
    check(f.investment.active() && !f.investment.state(0).collected[0] && f.ledger->snapshot(0).funds.cash==701,
        "investment_stale_plan_changed_collection_or_funds");
}
void overflow_and_zero_resource_values_are_explicit() {
    Fixture f;
    for(const auto position:{std::int16_t{173},std::int16_t{189}}) {
        f.entry.position=position; f.investment.begin(f.entry); f.investment.handle(decision(true));
    }
    const auto before=f.ledger->snapshot(0); auto funds=before.funds; funds.cash=maximum-300;
    f.ledger->commit(0,before,funds); const auto marks=f.investment.state(0);
    rejects([&]{f.investment.begin(f.entry);},"richonline_investment_reward_overflow");
    check(f.investment.state(0)==marks && f.ledger->snapshot(0).funds==funds && !f.investment.active(),
        "investment_overflow_reset_or_credited_assets");
    auto ledger=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{1,0,2,3}});
    RichonlineInvestment zero{game,{0,0,{173}},ledger,0xa5,[]{return RichonlineInvestment::Clock::time_point{};}};
    const RichonlineInvestmentEntry entry{0,173,calendar,RichonlineInvestmentVisit::landing,false,true};
    zero.begin(entry); const auto purchased=zero.handle(decision(true));
    check(purchased.after.collected[0] && purchased.funds_after.funds.cash==1,"resource_zero_cost_not_honored");
    const auto reset=zero.begin(entry);
    check(reset.outcome==RichonlineInvestmentOutcome::collection_reward && !reset.after.collected[0] &&
        reset.funds_after==reset.funds_before,"resource_zero_return_was_invented");
}
void rules_and_constructor_boundaries() {
    Fixture f; const auto now=[]{return RichonlineInvestment::Clock::time_point{};};
    rejects([&]{RichonlineInvestment bad(game,{1,1,{173}},nullptr,0xa5,now);},"richonline_investment_ledger_invalid");
    rejects([&]{RichonlineInvestment bad(game,{1,1,{173}},f.ledger,0xa5,{});},"richonline_investment_clock_required");
    rejects([&]{RichonlineInvestment bad(game,{maximum+1,1,{173}},f.ledger,0xa5,now);},"richonline_investment_rules_amount_invalid");
    rejects([&]{RichonlineInvestment bad(game,{1,maximum+1,{173}},f.ledger,0xa5,now);},"richonline_investment_rules_amount_invalid");
    rejects([&]{RichonlineInvestment bad(game,{1,1,{173,173}},f.ledger,0xa5,now);},"richonline_investment_rules_position_invalid");
    rejects([&]{RichonlineInvestment bad(game,{1,1,{-1}},f.ledger,0xa5,now);},"richonline_investment_rules_position_invalid");
    rejects([&]{RichonlineInvestment bad(game,{1,1,{0,1,2,3,4,5,6,7,8,9}},f.ledger,0xa5,now);},"richonline_investment_point_limit");
}
}
int main() {
    try {
        exact_requests_preserve_the_unknown_byte(); admission_and_completion_keep_original_route();
        complete_collection_pays_only_on_a_later_visit(); actors_have_independent_collections_and_cash();
        exact_threshold_and_static_guards_do_not_open_ui(); deterministic_timeout_and_synthetic_completion();
        malformed_and_stale_inputs_preserve_pending_state(); changed_shared_ledger_cannot_charge_or_collect();
        overflow_and_zero_resource_values_are_explicit(); rules_and_constructor_boundaries();
        std::cout<<"PASS NEW investment exact wire, actor collection, shared funds and route continuation\n";
    } catch(const std::exception& e) { std::cerr<<"FAIL "<<e.what()<<'\n'; return 1; }
}
