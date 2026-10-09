#include "original_god_state.hpp"
#include "codec.hpp"
#include <iostream>
#include <limits>

namespace {
using namespace richnet;
void check(bool condition, std::string_view reason) { if (!condition) throw std::runtime_error(std::string(reason)); }
template<class Action> void rejects(Action action, std::string_view code) {
    try { action(); } catch (const CodecError& error) { check(error.what() == code,"wrong god state rejection"); return; }
    throw std::runtime_error("expected god state rejection");
}
OriginalGodRules rules() {
    OriginalGodRules result{{1,2,3,4,5,6,7,8},{},5};
    for (auto& row : result.pyramid) row = {-1,-1,0,0,0,91,0,92,0,0};
    return result;
}
void state_fields_stay_independent() {
    const OriginalGodState original{4,2,3,75,1.75F};
    const auto detached = detach_original_god(original);
    check(detached == OriginalGodState{-1,-1,0,0,1.75F},"positive effect cleared but multiplier retained on detach");
    check(detach_original_god({2,7,-4,-23,-0.23F}) == OriginalGodState{-1,-1,0,-23,-0.23F},"negative effect preserved on detach");
    const auto resource = rules();
    const auto attached = attach_original_god(detached,6,2,resource.affix);
    check(attached == OriginalGodState{6,2,7,0,1.75F},"attachment replaces only three bytes and uses explicit NPC duration");
    check(original == OriginalGodState{4,2,3,75,1.75F},"state operations are pure");
    for (const std::int8_t kind : {std::int8_t{0},std::int8_t{1},std::int8_t{2},std::int8_t{3}})
        check(set_original_god_effect({kind,2,3,0,9.0F},25).multiplier == 0.25F,"effect percentage uses float division");
    for (const std::int8_t kind : {std::int8_t{4},std::int8_t{6}})
        check(set_original_god_effect({kind,2,3,0,9.0F},25).multiplier == 1.25F,"angel/devil modifier adds 100 before float division");
    check(set_original_god_effect({7,2,3,0,9.0F},25) == OriginalGodState{7,2,3,25,0.0F},"other gods store effect independently with zero computed multiplier");
    check(set_original_god_effect({0,2,3,0,9.0F},-25).multiplier == -0.25F,"effect setter retains signed input");
}
void pyramid_attachment_waits() {
    auto resource = rules();
    const OriginalGodState empty{-1,-1,0,7,0.7F};
    for (std::int8_t level = 1; level <= 7; ++level) {
        auto& row = resource.pyramid[static_cast<std::size_t>(level-1)]; row.enemy_summon = 6; row.friendly_summon = 4;
        const auto friendly = apply_original_pyramid(empty,level,true,false,resource);
        const auto enemy = apply_original_pyramid(empty,level,false,false,resource);
        check(friendly.state == OriginalGodState{4,2,5,7,0.7F} && enemy.state == OriginalGodState{6,2,7,7,0.7F} &&
              friendly.attached && enemy.attached && friendly.origin == OriginalGodOrigin::property &&
              friendly.wait == OriginalGodWait::none && finish_original_god_transition(enemy) == enemy.state,
              "all seven levels attach typed resource gods without magic duration or resetting effect");
    }
    for (const auto kind : {0,1,2,3}) {
        const bool friendly = kind == 0 || kind == 3;
        auto& row = resource.pyramid[6];
        if (friendly) row.friendly_summon = static_cast<std::int8_t>(kind); else row.enemy_summon = static_cast<std::int8_t>(kind);
        const auto pending = apply_original_pyramid(empty,7,friendly,false,resource);
        const auto expected = kind < 2 ? OriginalGodWait::wealth : kind == 2 ? OriginalGodWait::misfortune_cards : OriginalGodWait::blessing;
        check(pending.wait == expected,"attachment retains distinct mandatory followup");
        rejects([&] { finish_original_god_transition(pending); },"original_god_followup_pending");
        const auto flagged = apply_original_pyramid(empty,7,friendly,true,resource);
        check(flagged.wait == (kind < 2 ? OriginalGodWait::wealth : OriginalGodWait::none),"player state skips only blessing and misfortune waits");
    }
}
void pyramid_day_and_effect_changes() {
    auto resource = rules();
    auto& row = resource.pyramid[6];
    row.friendly_harmful_days = 1; row.enemy_beneficial_days = 2;
    row.friendly_beneficial_days = 3; row.friendly_beneficial_effect = 25;
    row.enemy_harmful_days = 2; row.enemy_harmful_effect = 50;
    auto result = apply_original_pyramid({2,2,5,33,0.33F},7,true,false,resource);
    check(result.state == OriginalGodState{2,2,3,33,0.33F} && !result.detached,"weaken subtracts configured days then performs extra day tick");
    result = apply_original_pyramid({0,2,3,33,0.33F},7,false,false,resource);
    check(result.detached && result.state == OriginalGodState{-1,-1,0,0,0.33F},"weaken expiry clears positive effect but preserves multiplier");
    result = apply_original_pyramid({4,2,4,0,8.0F},7,true,false,resource);
    check(result.state == OriginalGodState{4,2,5,25,1.25F},"friendly beneficial extends capped duration and computes effect");
    result = apply_original_pyramid({6,2,1,0,8.0F},7,false,false,resource);
    check(result.state == OriginalGodState{6,2,3,50,1.5F},"enemy harmful extends duration and computes effect");
    const OriginalGodState land_god{5,2,4,99,9.0F};
    check(apply_original_pyramid(land_god,7,true,false,resource).state == land_god &&
          apply_original_pyramid(land_god,7,false,false,resource).state == land_god,"land god excluded from both pyramid groups");
    row.friendly_harmful_days = 0;
    result = apply_original_pyramid({2,2,5,-7,-0.07F},7,true,false,resource);
    check(result.detached && result.state.effect == -7 && result.state.multiplier == -0.07F,"nonpositive weaken means immediate detach with negative effect retained");
    row.friendly_beneficial_days = 0; row.friendly_beneficial_effect = -1;
    const OriginalGodState prior{3,2,2,33,0.33F};
    check(apply_original_pyramid(prior,7,true,false,resource).state == prior,"nonpositive strengthen fields do not reset prior effect");
    row.friendly_beneficial_days = 127;
    check(apply_original_pyramid(prior,7,true,false,resource).state.days == -127,
          "client stores signed-byte addition before applying maximum-day cap");
    row.friendly_harmful_days = 255;
    check(apply_original_pyramid({2,2,5,0,0.0F},7,true,false,resource).state.days == 5,
          "weaken truncates subtraction to byte before subsequent expiration tick");
}
void invalid_inputs() {
    auto resource = rules(); const OriginalGodState empty{-1,-1,0,0,0.0F};
    rejects([&] { apply_original_pyramid(empty,0,true,false,resource); },"original_pyramid_level_invalid");
    rejects([&] { apply_original_pyramid(empty,8,true,false,resource); },"original_pyramid_level_invalid");
    rejects([&] { attach_original_god(empty,8,2,resource.affix); },"original_god_kind_invalid");
    rejects([] { detach_original_god({8,2,1,0,0.0F}); },"original_god_state_invalid");
    rejects([] { detach_original_god({0,2,1,0,std::numeric_limits<float>::infinity()}); },"original_god_state_invalid");
    resource.pyramid[0].friendly_summon = 2;
    rejects([&] { apply_original_pyramid(empty,1,true,false,resource); },"original_pyramid_summon_invalid");
}
void ordinary_turn_tick() {
    auto result = advance_original_god({6,2,2,75,1.75F});
    check(result.state == OriginalGodState{6,2,1,75,1.75F} && !result.expired_kind,
          "ordinary recipient turn decrements active god without changing independent fields");
    result = advance_original_god(result.state);
    check(result.state == OriginalGodState{-1,-1,0,0,1.75F} && result.expired_kind == 6,
          "expiry retains old god kind while detach clears positive effect and leaves multiplier");
    result = advance_original_god({2,7,0,-25,-0.25F});
    check(result.state == OriginalGodState{-1,-1,0,-25,-0.25F} && result.expired_kind == 2,
          "zero days decrements then expires and retains negative effect");
    result = advance_original_god({4,2,-128,0,9.0F});
    check(result.state == OriginalGodState{4,2,127,0,9.0F} && !result.expired_kind,
          "signed-byte -128 wraps to127 before expiry comparison");
    const OriginalGodState absent{-1,7,-43,75,1.75F};
    result = advance_original_god(absent);
    check(result.state == absent && !result.expired_kind,
          "unattached god does not tick or normalize anomalous residual fields");
}
}
int main() {
    try {
        state_fields_stay_independent(); pyramid_attachment_waits(); pyramid_day_and_effect_changes(); invalid_inputs(); ordinary_turn_tick();
        std::cout << "PASS original god independent state, seven pyramid levels, explicit durations and pending continuations\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
