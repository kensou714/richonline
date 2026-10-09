#include "original_god_event.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool ok, const char* reason) { if (!ok) throw std::runtime_error(reason); }
template<class F> void rejects(F action, std::string_view reason) {
    try { action(); } catch (const CodecError& error) {
        if (error.what() != reason) throw std::runtime_error(std::string("expected ")+std::string(reason)+", got "+error.what()); return;
    }
    throw std::runtime_error("expected rejection missing");
}
OriginalGodEventSetup setup(std::int8_t god, OriginalGodWait wait, OriginalGodOrigin origin) {
    return {0x3456,77,0,{{god,2,5,0,0.0F},origin,wait,true,false}};
}
void rewards_clear_only_matching_wait() {
    for (const auto origin : {OriginalGodOrigin::landing,OriginalGodOrigin::card,OriginalGodOrigin::property}) {
        auto inventory = make_original_inventory();
        OriginalGodEvent event(setup(3,OriginalGodWait::blessing,origin));
        rejects([&] { event.finish(); },"original_god_followup_pending");
        rejects([&] { event.discard(inventory,{-1,-1,-1,-1}); },"original_god_misfortune_not_pending");
        rejects([&] { event.bless(inventory,{1044,-1},{},{}); },"original_blessing_card_invalid");
        check(event.transition().wait == OriginalGodWait::blessing,"failed reward retains wait");
        const auto result = event.bless(inventory,{1044,1038},{},{});
        check(result.inventory[0].id == 1044 && result.inventory[1].id == 1038 && event.finish() == origin,
            "successful reward releases original phase without extra4015 or4010");
        rejects([&] { event.bless(inventory,{1044,1038},{},{}); },"original_god_blessing_not_pending");
        OriginalGodEvent bad(setup(2,OriginalGodWait::misfortune_cards,origin));
        inventory[2] = {1044,2,{0x81,0x92}};
        const auto lost = bad.discard(inventory,{2,2,-1,-1});
        check(lost.inventory[2].id == -1 && bad.finish() == origin,"misfortune preserves origin after actual deletion");
    }
}
void wealth_requires_real_bankruptcy_completion() {
    OriginalGodEvent event(setup(0,OriginalGodWait::wealth,OriginalGodOrigin::property));
    const OriginalWealthSnapshot snapshot{77,0,{{{100,0,0},1,true,0},{{10,0,0},2,true,-1}}};
    rejects([&] { event.settle({78,1,0},snapshot,30); },"original_wealth_context_mismatch");
    const auto result = event.settle({77,1,0xce},snapshot,30);
    check(result.players[0].funds.cash == 130 && result.players[1].funds.cash == 0 && result.bankruptcy_wait &&
        event.awaiting_bankruptcy(),"wealth insolvency retains effect waiting");
    rejects([&] { event.finish(); },"original_god_followup_pending");
    rejects([&] { event.settle({77,1,0},snapshot,30); },"original_wealth_choice_not_pending");
    rejects([&] { event.finish_bankruptcy(78); },"original_wealth_context_mismatch");
    event.finish_bankruptcy(77);
    check(event.finish() == OriginalGodOrigin::property && !event.awaiting_bankruptcy(),"owner completion returns property phase");
    rejects([&] { event.finish_bankruptcy(77); },"original_wealth_bankruptcy_not_pending");
}
void invalid_pending_kind_rejected() {
    rejects([] { OriginalGodEvent event(setup(1,OriginalGodWait::blessing,OriginalGodOrigin::landing)); },"original_god_event_kind_mismatch");
    rejects([] { OriginalGodEvent event(setup(3,OriginalGodWait::misfortune_cards,OriginalGodOrigin::landing)); },"original_god_event_kind_mismatch");
    OriginalGodEvent complete(setup(4,OriginalGodWait::none,OriginalGodOrigin::property));
    check(complete.finish() == OriginalGodOrigin::property,"synchronous pyramid effect needs no fabricated packet");
}
}
int main() {
    try { rewards_clear_only_matching_wait(); wealth_requires_real_bankruptcy_completion(); invalid_pending_kind_rejected();
        std::cout << "PASS god event origin, single completion and bankruptcy lifetime.\n"; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
