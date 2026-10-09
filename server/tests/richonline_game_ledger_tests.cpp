#include "richonline_game_ledger.hpp"
#include "richonline_boss_property.hpp"
#include "richonline_boss_landing.hpp"
#include "richonline_boss_stage.hpp"
#include <iostream>
#include <limits>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if (!value) throw std::runtime_error(reason); }
template<class F> void rejects(F action,const char* code) {
    try { action(); } catch (const CodecError& error) { check(std::string(error.what())==code,error.what()); return; }
    throw std::runtime_error("expected_ledger_rejection");
}
void commit_is_atomic_and_rejects_stale_aba() {
    RichonlineGameLedger ledger({{700,300,150,20},{100000,0,0,0}});
    const auto before=ledger.snapshot(0);
    auto transferred=before.funds; transferred.cash=600; transferred.deposit=400;
    const auto saved=ledger.commit(0,before,transferred);
    check(saved.funds==transferred && saved.revision==1 && ledger.snapshot(1).funds.cash==100000,"transfer_not_isolated");
    rejects([&] { ledger.commit(0,before,before.funds); },"richonline_game_ledger_conflict");
    const auto restored=ledger.commit(0,saved,before.funds);
    rejects([&] { ledger.commit(0,before,transferred); },"richonline_game_ledger_conflict");
    check(ledger.snapshot(0)==restored && restored.revision==2,"ABA_not_detected");
    check(ledger.commit(0,restored,restored.funds)==restored,"no_op_changed_revision");
}
void failed_adjustments_never_partially_commit() {
    constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    RichonlineGameLedger ledger({{700,300,maximum,20}});
    const auto before=ledger.snapshot(0);
    rejects([&] { ledger.adjust(0,before,{-10,10,1,0}); },"richonline_game_ledger_overflow");
    rejects([&] { ledger.adjust(0,before,{-701,701,0,0}); },"richonline_game_ledger_insufficient");
    rejects([&] { ledger.adjust(0,before,{std::numeric_limits<std::int64_t>::min(),0,0,0}); },"richonline_game_ledger_insufficient");
    rejects([&] { ledger.adjust(0,before,{std::numeric_limits<std::int64_t>::max(),0,0,0}); },"richonline_game_ledger_overflow");
    auto bad=before.funds; bad.reserve=maximum+1;
    rejects([&] { ledger.commit(0,before,bad); },"richonline_game_ledger_balance_invalid");
    rejects([&] { ledger.snapshot(1); },"richonline_game_ledger_actor_invalid");
    rejects([&] { ledger.commit(1,before,before.funds); },"richonline_game_ledger_actor_invalid");
    check(ledger.snapshot(0)==before,"failed_adjustment_mutated_ledger");
    rejects([&] { RichonlineGameLedger invalid({}); },"richonline_game_ledger_actor_count_invalid");
    rejects([&] { RichonlineGameLedger invalid(std::vector<RichonlineGameFunds>(9)); },"richonline_game_ledger_actor_count_invalid");
    rejects([&] { RichonlineGameLedger invalid({{maximum+1,{},0,{}}}); },"richonline_game_ledger_balance_invalid");
}
void unknown_balances_stay_unknown() {
    RichonlineGameLedger ledger({{700,{},150,{}}});
    const auto before=ledger.snapshot(0);
    rejects([&] { ledger.adjust(0,before,{0,1,0,0}); },"richonline_game_ledger_balance_unknown");
    rejects([&] { ledger.adjust(0,before,{0,0,0,-1}); },"richonline_game_ledger_balance_unknown");
    auto guessed=before.funds; guessed.deposit=0;
    rejects([&] { ledger.commit(0,before,guessed); },"richonline_game_ledger_knowledge_change");
    const auto after=ledger.adjust(0,before,{-100,0,30,0});
    check(after.funds.cash==600 && after.funds.tickets==180 && !after.funds.deposit && !after.funds.reserve,
        "known_currency_update_guessed_unknown_balance");
}
void property_and_landing_observe_one_authoritative_ledger(const std::filesystem::path& root) {
    auto ledger=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{20000,300,150,20},{100000,0,0,0}});
    const auto stage=load_richonline_boss_stage(root,"BS_1_1.emp");
    RichonlineBossProperty properties(root,0x1234,ledger,stage);
    RichonlineBossLandingState landing(0x1234,ledger);
    const auto original=ledger->snapshot(1);
    ledger->adjust(1,original,{-99899,0,0,0});
    const auto bought=properties.land({1,231,33,216,3,true,2,false});
    check(bought && properties.owner(216)==1 && properties.cash()[1]==1 && ledger->snapshot(1).funds.cash==1,
        "property_used_stale_cash_copy");
    const auto human=ledger->snapshot(0);
    ledger->adjust(0,human,{0,0,100,0});
    landing.land({0,25,7,-1,3,false,2,false});
    check(landing.points()[0]==280 && ledger->snapshot(0).funds==RichonlineGameFunds{20000,300,280,20},
        "landing_reward_did_not_preserve_other_currencies");
    landing.commit_points(0,280,240);
    check(ledger->snapshot(0).funds.tickets==240,"shop_point_commit_missed_shared_ledger");
    rejects([&] { landing.commit_points(0,280,0); },"richonline_boss_points_changed");
    properties.enable_human_decisions(std::chrono::seconds{10},[] { return RichonlineBossProperty::Clock::time_point{}; });
    const auto pending=properties.land({0,162,36,164,3,false,2,false});
    check(pending && pending->progress==RichonlineLandingProgress::await_event,"human_purchase_not_pending");
    const auto before_debit=ledger->snapshot(0);
    ledger->adjust(0,before_debit,{-19900,0,0,0});
    const auto declined=properties.decide(Bytes{0x20,0,1,0,0,0,0,0,1,0xcc,0xcc,0xcc});
    check(declined.messages[0].back()==0 && !properties.owner(164) && ledger->snapshot(0).funds.cash==100,
        "pending_purchase_ignored_current_shared_balance");
    const auto state=ledger->snapshot(1);
    for (const auto tile:{std::int8_t{41},std::int8_t{42}}) {
        const auto result=landing.land({1,25,tile,-1,3,true,2,false});
        check(result.messages==std::vector<Bytes>{{0x13,0x40,0x34,0x12,25,0}} &&
            result.progress==RichonlineLandingProgress::complete && ledger->snapshot(1)==state,
            "synthetic_card_tile_awarded_or_stalled");
    }
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_root_required");
        commit_is_atomic_and_rejects_stale_aba(); failed_adjustments_never_partially_commit();
        unknown_balances_stay_unknown(); property_and_landing_observe_one_authoritative_ledger(argv[1]);
        std::cout<<"PASS NEW shared ledger CAS, currency isolation and property/landing integration\n";
    } catch (const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
