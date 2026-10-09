#include "original_boss_match_test_support.hpp"
#include <iostream>

namespace {
using namespace original_boss_match_test;
std::vector<std::uint32_t> opcodes(const std::vector<Bytes>& messages) {
    std::vector<std::uint32_t> result;
    for (const auto& message : messages) result.push_back(read_le(View(message).first(2)));
    return result;
}
void boss_shop_closes_before_human_turn() {
    Fixture fixture({123,1},{179,1});
    auto& match = *fixture.match;
    match.start();
    const auto responses = match.action(Bytes{17,0,0,0,178,0});
    require(opcodes(responses) == std::vector<std::uint32_t>{0x4013,0x4030,0x4031,0x4010,0x420f},
        "boss_shop_must_close_and_skip_human_fork");
    require(responses[2][4] == 0xff && match.current_slot() == 0 && match.phase() == OriginalBossMatchPhase::dice,
        "boss_shop_kept_pending_or_waited_for_direction");
    require(match.context() == 0x12350001 && match.actor(1).funds.tickets == fixture.expected_startup.snapshot.per_player[1].tickets,
        "boss_shop_changed_wallet_or_wrong_context");
}
void human_property_waits_and_commits_once() {
    Fixture fixture({118,3},{123,3});
    auto& match = *fixture.match;
    match.start(); match.action(Bytes{17,0,0,0,124,0});
    match.action(Bytes{16,0,1,0,0,0,0,0});
    const auto landing = match.action(Bytes{17,0,1,0,119,0});
    require(opcodes(landing) == std::vector<std::uint32_t>{0x4013} && match.phase() == OriginalBossMatchPhase::property,
        "purchase_did_not_keep_turn_pending");
    require(match.poll().empty() && match.context() == 0x12350001,"purchase_advanced_without_choice");
    const auto before = match.actor(0).funds.cash;
    const auto purchased = match.action(Bytes{32,0,1,0,0,0,0,0,1,0x81,0x92,0xa3});
    require(opcodes(purchased) == std::vector<std::uint32_t>{0x4020,0x4010,0x420f,0x4011},"purchase_continuation_wrong");
    require(match.actor(0).funds.cash == before-100,"purchase_not_mirrored_once");
    match.action(Bytes{17,0,2,0,125,0});
    match.action(Bytes{16,0,3,0,0,0,0,0});
    require(opcodes(match.action(Bytes{17,0,3,0,120,0})) == std::vector<std::uint32_t>{0x4013},"build_not_pending");
    const auto built = match.action(Bytes{55,0,3,0,11,0xa1});
    require(opcodes(built) == std::vector<std::uint32_t>{0x403d,0x4010,0x420f,0x4011},"build_continuation_wrong");
    const auto property = std::find_if(match.properties().begin(),match.properties().end(),[](const auto& item) { return item.id == 104; });
    require(property != match.properties().end() && property->owner == 0 && property->kind == 11 && property->level == 1,
        "actual_property_record_not_updated");
    require(match.actor(0).funds.cash == before-100,"free_build_charged_cash");
}
void boss_property_has_no_human_wait() {
    Fixture fixture({179,1},{118,3});
    fixture.match->start();
    const auto replies = fixture.match->action(Bytes{17,0,0,0,119,0});
    require(opcodes(replies) == std::vector<std::uint32_t>{0x4013,0x4020,0x4010,0x420f},"boss_purchase_waited_for_human");
    require(fixture.match->actor(1).funds.cash == fixture.expected_startup.snapshot.per_player[1].cash-100,"boss_purchase_cash_wrong");
}
void reward_and_discard_preserve_turn() {
    Fixture fixture({115,3},{123,3});
    auto& match = *fixture.match;
    match.start(); match.action(Bytes{17,0,0,0,124,0});
    const auto context = match.context();
    const auto dropped = match.action(Bytes{50,0,1,0,0,0xa1});
    require(opcodes(dropped) == std::vector<std::uint32_t>{0x4033} && match.actor(0).inventory[0].id == -1 &&
        match.context() == context && match.phase() == OriginalBossMatchPhase::dice,"discard_broke_turn");
    match.action(Bytes{16,0,1,0,0,0,0,0});
    const auto granted = match.action(Bytes{17,0,1,0,116,0});
    require(opcodes(granted) == std::vector<std::uint32_t>{0x4013,0x4029,0x4010,0x420f,0x4011},"card_landing_did_not_resume");
    const auto card = static_cast<std::int16_t>(read_le(View(granted[1]).subspan(4,2)));
    require(card >= 0 && match.actor(0).inventory[0].id == card,"card_grant_not_mirrored_in_reused_slot");
}
void unsupported_attack_is_not_silently_disabled() {
    rejects([] { Fixture fixture({179,1},{123,1},4); },"original_boss_attack_strategy_unavailable");
}
void refresh_uses_four_byte_request_and_returns_to_fork() {
    Fixture fixture({179,1},{123,3});
    auto& match = *fixture.match;
    match.start(); match.action(Bytes{17,0,0,0,124,0});
    match.action(Bytes{16,0,1,0,0,0,0,0}); match.action(Bytes{17,0,1,0,178,0});
    const auto tickets = match.actor(0).funds.tickets;
    const auto inventory = match.actor(0).inventory;
    const auto result = match.action(Bytes{53,0,1,0});
    require(opcodes(result) == std::vector<std::uint32_t>{0x4031} && result[0][4] == 0xff,
        "unknown_refresh_price_must_close_without_paid_success");
    require(match.context() == 0x12350001 && match.phase() == OriginalBossMatchPhase::direction &&
        match.actor(0).funds.tickets == tickets && match.actor(0).inventory == inventory,"refresh_rejection_changed_wallet_or_skipped_fork");
}
void closed_shop_grace_is_bounded_and_validates_requests() {
    Fixture fixture({179,1},{123,3});
    auto& match = *fixture.match;
    match.start(); match.action(Bytes{17,0,0,0,124,0});
    match.action(Bytes{16,0,1,0,0,0,0,0}); match.action(Bytes{17,0,1,0,178,0});
    fixture.seconds.store(10); match.poll();
    rejects([&] { match.action(Bytes{48,0,1,0,12,0xa1}); },"original_shop_index_invalid");
    rejects([&] { match.action(Bytes{53,0,1,0,0}); },"original_shop_request_length_invalid");
    require(match.action(Bytes{49,0,1,0,0,0xa1}).empty(),"valid_expired_sale_not_ignored");
    fixture.seconds.store(20);
    rejects([&] { match.action(Bytes{49,0,1,0,0,0xa1}); },"original_boss_match_shop_not_pending");
    require(!match.closed_shop_context(),"shop_grace_outlived_deadline");
    Fixture automated({123,1},{179,1});
    automated.match->start(); automated.match->action(Bytes{17,0,0,0,178,0});
    require(!automated.match->closed_shop_context(),"boss_shop_created_human_grace");
}
}
int main() {
    try {
        boss_shop_closes_before_human_turn(); human_property_waits_and_commits_once();
        boss_property_has_no_human_wait(); reward_and_discard_preserve_turn(); unsupported_attack_is_not_silently_disabled();
        refresh_uses_four_byte_request_and_returns_to_fork();
        closed_shop_grace_is_bounded_and_validates_requests();
        std::cout << "PASS original BOSS real-map shop, property, reward and inventory scheduling.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
