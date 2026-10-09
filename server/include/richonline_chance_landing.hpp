#pragma once
#include "richonline_actor_status.hpp"
#include "richonline_boss_turns.hpp"
#include "richonline_game_ledger.hpp"

namespace richnet {
struct RichonlineChanceLandingEntry {
    std::int16_t event;
    std::uint32_t server_weight;
};
struct RichonlineChanceLandingPolicy {
    std::string name;
    std::string map_name;
    std::vector<RichonlineChanceLandingEntry> entries;
    std::vector<std::int16_t> playable_reward_cards;
    std::vector<std::int8_t> static_types;
    bool enable_motion_status=false;
    std::array<std::uint8_t,2> opaque6_7;
};
enum class RichonlineChanceLandingDisposition { not_applicable, prepared, no_closed_event };
struct RichonlinePreparedChanceLanding {
    std::uint8_t actor;
    std::int16_t event;
    std::uint8_t category;
    std::string policy;
    Bytes packet;
    RichonlineGameFundsSnapshot expected_funds;
    RichonlineGameFunds updated_funds;
    RichonlineChanceInventory expected_inventory,updated_inventory;
    RichonlineActorStatus expected_status,updated_status;
};
struct RichonlineChanceLandingAttempt {
    RichonlineChanceLandingDisposition disposition;
    std::optional<RichonlinePreparedChanceLanding> prepared;
    std::vector<std::string> excluded_events;
};
// Explicit policy: blue68/red69/yellow70 use BwNews columns0/1/2 as eligibility.
// Equal server weights and uniform integer/card choices remain native policy;
// original server probabilities are not recovered from the skipped columns.
RichonlineChanceLandingPolicy make_richonline_closed_chance_policy(
    const RichonlineChanceEventTable&,std::string_view map,
    std::vector<std::int16_t> playable_cards,bool motion_status,
    std::array<std::uint8_t,2> opaque6_7);
// Pure preparation: no independent balance/status store and no side effects.
// Only ready money/card/one-six-turtle events enter the lottery. Insolvency,
// unsupported synthesized rewards and unsafe presentation are excluded first.
// Owner CAS-checks all snapshots, commits, sends4096, then continues property /
// junction phases; this function never declares a whole landing/turn complete.
RichonlineChanceLandingAttempt prepare_richonline_chance_landing(
    const RichonlineChanceEventTable&,const RichonlineChanceResources&,
    const RichonlineStatusRules&,const RichonlineChanceLandingPolicy&,
    const RichonlineLandingContext&,std::uint16_t game_id,
    const RichonlineGameFundsSnapshot&,const RichonlineChanceInventory&,
    const RichonlineRouteChooser& random);
}
