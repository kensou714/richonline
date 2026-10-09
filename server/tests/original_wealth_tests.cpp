#include "original_wealth.hpp"
#include <functional>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value, std::string_view message) {
    if (!value) throw std::runtime_error(std::string(message));
}
void rejects(const std::function<void()>& action, std::string_view code) {
    try { action(); } catch (const CodecError& error) {
        check(error.what() == code,std::string("unexpected rejection: ")+error.what()); return;
    }
    throw std::runtime_error("expected rejection missing");
}
OriginalWealthSnapshot snapshot(std::int8_t god = 0) {
    return {0x1234,0,{{{100,40,9},1,true,god},{{500,60,8},2,true,-1},
        {{600,70,7},2,true,-1},{{700,80,6},1,true,-1},{{800,90,5},3,false,-1}}};
}
OriginalWealthSettlement pending(std::int8_t god = 0, OriginalWealthOrigin origin = OriginalWealthOrigin::landing) {
    OriginalWealthSettlement value;
    value.begin({0x1234,0,god,origin});
    return value;
}
constexpr OriginalWealthChoice choice{0x1234,1,0xa5};
void test_wealth_multiplayer_distribution() {
    auto flow = pending(); const auto before = snapshot();
    const auto outcome = flow.resolve(choice,before,101);
    check(outcome.players[0].funds.cash == 201 && outcome.players[1].funds.cash == 450 &&
        outcome.players[2].funds.cash == 550,"god0 actor getsfull and opponents lose truncated share");
    check(outcome.players[3].funds.cash == 700 && outcome.players[4].funds.cash == 800,"god0 excludes teammate and inactive");
    check(outcome.players[0].funds.deposit == 40 && outcome.players[0].funds.tickets == 9 &&
        outcome.players[1].funds.deposit == 60 && outcome.players[1].funds.tickets == 8,"deposit/tickets unaffected by affordable cashtransfer");
    check(outcome.amount == 101 && !outcome.bankruptcy_wait && outcome.bankrupt_slots.empty() &&
        outcome.continuation == OriginalWealthContinuation::landing && !flow.pending(),"completedwealth resumeslanding");
    check(before.players[0].funds.cash == 100 && before.players[1].funds.cash == 500,"caller snapshot remains unchanged");
    rejects([&] { flow.resolve(choice,before,101); },"original_wealth_choice_not_pending");
}
void test_poverty_multiplayer_distribution() {
    auto flow = pending(1,OriginalWealthOrigin::card); const auto before = snapshot(1);
    const auto outcome = flow.resolve(choice,before,101);
    check(outcome.players[0].funds.cash == 0 && outcome.players[0].funds.deposit == 39,"god1 depletescash beforedeposit");
    check(outcome.players[1].funds.cash == 533 && outcome.players[2].funds.cash == 633 &&
        outcome.players[3].funds.cash == 733 && outcome.players[4].funds.cash == 800,"god1 creditsall aliveothers includingteammate");
    check(!outcome.bankruptcy_wait && outcome.continuation == OriginalWealthContinuation::card,"summonedgod resumescardchain");
}
void test_bankruptcy_waits_and_release() {
    auto flow = pending(0,OriginalWealthOrigin::property); auto before = snapshot();
    before.players[1].funds = {2,3,8}; before.players[2].funds = {50,0,7};
    const auto outcome = flow.resolve(choice,before,100);
    check(outcome.players[0].funds.cash == 200 && outcome.players[1].funds.cash == 0 &&
        outcome.players[1].funds.deposit == 0 && outcome.players[2].funds.cash == 0,"payerfunds clampzero, fullcredit remains");
    check(outcome.bankrupt_slots == std::vector<std::uint8_t>{1,2} && outcome.bankruptcy_wait &&
        outcome.continuation == OriginalWealthContinuation::bankruptcy && flow.pending() && flow.awaiting_bankruptcy(),
        "all bankruptpayers wait before propertycontinuation");
    rejects([&] { flow.resolve(choice,before,100); },"original_wealth_choice_not_pending");
    rejects([&] { flow.begin({0x1235,0,0,OriginalWealthOrigin::landing}); },"original_wealth_already_pending");
    rejects([&] { flow.finish_bankruptcy(0x9999); },"original_wealth_context_mismatch");
    check(flow.awaiting_bankruptcy(),"invalidrelease preservespending");
    check(flow.finish_bankruptcy(0x1234) == OriginalWealthContinuation::property && !flow.pending() && !flow.awaiting_bankruptcy(),
        "explicit caller bankruptcycompletion returns propertyorigin");
    rejects([&] { flow.finish_bankruptcy(0x1234); },"original_wealth_bankruptcy_not_pending");
    auto poverty = pending(1); before = snapshot(1);
    const auto poor = poverty.resolve(choice,before,140);
    check(poor.bankrupt_slots == std::vector<std::uint8_t>{0} && poor.bankruptcy_wait && poverty.awaiting_bankruptcy(),
        "god1 actor exactzero triggers unconditional bankruptcywait");
    check(poor.players[1].funds.cash == 546 && poor.players[3].funds.cash == 746,"god1 recipientcredit before bankruptactorcontinuation");
}
void test_zero_enemy_and_zero_amount() {
    auto flow = pending(); auto before = snapshot();
    for (auto& player : before.players) player.team = 1;
    const auto outcome = flow.resolve(choice,before,77);
    check(outcome.players[0].funds.cash == 177 && outcome.players[1].funds.cash == 500 &&
        !outcome.bankruptcy_wait,"raw625730 zeroenemy stillcredits actorfull without transfers");
    flow = pending(); before = snapshot(); before.players[1].funds = {0,0,8};
    const auto zero = flow.resolve(choice,before,0);
    check(zero.bankrupt_slots == std::vector<std::uint8_t>{1},"744FB0 zero debit at zero total stillreportsbankruptcy");
}
void test_rejected_requests_are_atomic() {
    auto flow = pending(); const auto before = snapshot();
    rejects([&] { flow.resolve({0xffff,1,0},before,1); },"original_wealth_context_mismatch");
    rejects([&] { flow.resolve({0x1234,0,0},before,1); },"original_wealth_action_invalid");
    for (const auto amount : {-1,32768})
        rejects([&] { flow.resolve(choice,before,amount); },"original_wealth_amount_invalid");
    auto invalid = before; invalid.context = 0;
    rejects([&] { flow.resolve(choice,invalid,1); },"original_wealth_snapshot_mismatch");
    invalid = before; invalid.actor = 1;
    rejects([&] { flow.resolve(choice,invalid,1); },"original_wealth_snapshot_mismatch");
    invalid = before; invalid.players[0].god = 1;
    rejects([&] { flow.resolve(choice,invalid,1); },"original_wealth_actor_mismatch");
    invalid = before; invalid.players[0].alive = false;
    rejects([&] { flow.resolve(choice,invalid,1); },"original_wealth_actor_mismatch");
    invalid = before; for (std::size_t i = 1; i < invalid.players.size(); ++i) invalid.players[i].alive = false;
    rejects([&] { flow.resolve(choice,invalid,1); },"original_wealth_insufficient_active_players");
    invalid = before; invalid.players.resize(9);
    rejects([&] { flow.resolve(choice,invalid,1); },"original_wealth_players_invalid");
    invalid = before; invalid.players[0].funds.cash = 0x80000000U;
    rejects([&] { flow.resolve(choice,invalid,1); },"original_wealth_funds_invalid");
    invalid = before; invalid.players[0].funds.cash = 0x7fffffffU;
    rejects([&] { flow.resolve(choice,invalid,1); },"original_wealth_cash_overflow");
    check(flow.pending() && !flow.awaiting_bankruptcy(),"all failedrequests preserve original transactionstate");
    const auto outcome = flow.resolve(choice,before,32767);
    check(outcome.players[0].funds.cash == 32867 && outcome.amount == 32767,"validretry usesoriginal state at signed16amount boundary");
    auto poverty = pending(1); invalid = snapshot(1); invalid.players[2].funds.cash = 0x7fffffffU;
    rejects([&] { poverty.resolve(choice,invalid,30); },"original_wealth_cash_overflow");
    check(poverty.pending() && invalid.players[1].funds.cash == 500 && invalid.players[0].funds.cash == 100,
        "failure after firstcopiedcredit exposesno partial updates");
}
void test_pending_validation() {
    OriginalWealthSettlement flow;
    rejects([&] { flow.begin({0,8,0,OriginalWealthOrigin::landing}); },"original_wealth_pending_invalid");
    rejects([&] { flow.begin({0,0,2,OriginalWealthOrigin::landing}); },"original_wealth_pending_invalid");
    rejects([&] { flow.begin({0,0,0,static_cast<OriginalWealthOrigin>(99)}); },"original_wealth_origin_invalid");
    rejects([&] { flow.resolve(choice,snapshot(),1); },"original_wealth_choice_not_pending");
    check(!flow.pending(),"invalidbegin preservesidlestate");
    flow.begin({0x1234,3,1,OriginalWealthOrigin::landing});
    auto before = snapshot(); before.actor = 3; before.players[3].god = 1;
    const auto result = flow.resolve(choice,before,30);
    check(result.players[3].funds.cash == 670 && result.players[0].funds.cash == 110 && result.players[2].funds.cash == 610,
        "arbitrary actor slot is debited; allotheralive recipientscredited");
}
}
int main() {
    try {
        test_wealth_multiplayer_distribution(); test_poverty_multiplayer_distribution(); test_bankruptcy_waits_and_release();
        test_zero_enemy_and_zero_amount(); test_rejected_requests_are_atomic(); test_pending_validation();
        std::cout << "PASS original multiplayer wealth/poverty distribution, bankruptcy continuation and atomic validation.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
