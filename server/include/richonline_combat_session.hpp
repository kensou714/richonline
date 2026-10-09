#pragma once

#include "richonline_combat.hpp"

namespace richnet {
// These are snapshots of the session's shared stores, never a second status or
// inventory authority. The session serializes preparation, commit and broadcast.
struct RichonlineCombatActorView {
    std::uint8_t slot=0;
    RichonlineActorStatus status{};
    RichonlineGameFundsSnapshot funds{};
    RichonlineChanceInventory inventory{};
    RichonlineCombatModifiers attack_modifiers{},defense_modifiers{};
    std::int32_t flat_attack=0,flat_defense=0;
    bool active=true,in_hospital=false,in_prison=false,mine_immune_vehicle=false;
    bool attack_modifiers_enabled=true;
    std::int16_t position=-1;
    // Shared timed-building buff sources (actor+1730/+1734), not all owned
    // buildings. A blast invalidates the active source even when a level remains.
    std::optional<std::uint32_t> attack_building_source,defense_building_source;
};
struct RichonlineCombatBuildingView {
    std::uint32_t property=0;
    std::vector<std::int16_t> footprint;
    std::int8_t kind=0;
    std::uint8_t level=0;
    std::optional<std::uint8_t> owner;
    bool ownership_protected=false;
    bool operator==(const RichonlineCombatBuildingView&) const = default;
};
struct RichonlineCombatDynamicView {
    std::int16_t position;
    std::uint8_t type;
};
struct RichonlineCombatSessionView {
    std::uint16_t game_id=0;
    std::uint64_t revision=0;
    std::array<std::optional<RichonlineCombatActorView>,8> actors{};
    RichonlineMineSnapshot mines;
    std::vector<RichonlineCombatBuildingView> buildings;
    std::vector<RichonlineCombatDynamicView> dynamic_npcs;
};
struct RichonlineCombatWorld {
    std::uint16_t width=0,height=0;
    RichonlineCombatResources resources{};
    RichonlineCombatStep step;
    // Actual legal visible tiles, including the attacker's own tile when legal.
    // Called again after each attack; no cached actor-target list is used.
    std::function<std::vector<std::int16_t>(std::uint8_t,RichonlineCombatEffect,
        const RichonlineCombatSessionView&)> targets;
    // Human inventory cards have their own authorization policy. NEW missile
    // resources permit whole-map targeting; BOSS visibility policy must not
    // silently replace that card rule.
    std::function<std::vector<std::int16_t>(std::uint8_t,RichonlineCombatEffect,
        const RichonlineCombatSessionView&)> card_targets;
    // Pure activation through shared card rules. The actor carries the same
    // per-game usage count and inventory that this prepared plan will commit.
    std::function<std::optional<RichonlineBossCards::PreparedConsumption>(
        const RichonlineCombatActorView&,const RichonlineCombatSessionView&)> helmet;
    // Pure property adapter normalizes building kind/production on level zero.
    std::function<RichonlineCombatBuildingView(const RichonlineCombatBuildingView&,
        RichonlineBossBlastBuildingEffect)> building;
    struct ResolvedTerms {
        RichonlineCombatModifiers attack,defense;
        std::int32_t flat_attack,flat_defense;
    };
    // Optional pure adapter for cash-dependent equipment and active building
    // buffs. Re-evaluated before each attack/chain using the current snapshot.
    std::function<ResolvedTerms(const RichonlineCombatActorView&,
        const RichonlineCombatSessionView&)> resolve_terms;
};
struct RichonlineBossAttackRandomness {
    // Independent categorical draws: 0..79 none,80..89 mine,90..99 projectile.
    std::array<std::uint8_t,4> rolls{};
    // Return a uniform integer in [0,bound). Called at the point of selection,
    // after earlier attacks changed the world. No biased modulo reduction.
    std::function<std::size_t(std::size_t)> bounded;
};
struct RichonlineBossCombatPolicy {
    // Explicit stage policy. A multi-entry list selects uniformly; no hidden
    // assumption about the relative missile/nuclear probabilities.
    std::vector<RichonlineCombatEffect> projectiles{RichonlineCombatEffect::missile};
};
enum class RichonlineCombatAttemptOutcome { none,executed,controlled,no_legal_target,actor_eliminated };
struct RichonlineCombatAttackAttempt {
    RichonlineCombatAttemptOutcome outcome=RichonlineCombatAttemptOutcome::none;
    std::optional<RichonlineCombatEffect> effect;
    std::optional<std::int16_t> target;
};
struct RichonlineCombatCardConsumption {
    std::uint8_t actor;
    RichonlineBossCards::PreparedConsumption consumption;
};
struct RichonlineCombatTurnPlan {
    RichonlineCombatSessionView expected,after;
    std::array<RichonlineCombatAttackAttempt,4> boss_attempts{};
    std::vector<RichonlineGameFundsUpdate> funds_updates;
    std::vector<RichonlineCombatCardConsumption> card_consumptions;
    std::vector<std::uint8_t> bankrupt_actors;
    std::vector<Bytes> packets;
    bool committed=false;
};
RichonlineCombatTurnPlan prepare_richonline_boss_combat_turn(const RichonlineCombatSessionView&,
    const RichonlineCombatWorld&,std::uint8_t boss,const RichonlineBossAttackRandomness&,
    const RichonlineBossCombatPolicy& = {});
RichonlineCombatTurnPlan prepare_richonline_combat_human_card(const RichonlineCombatSessionView&,
    const RichonlineCombatWorld&,std::uint8_t actor,const RichonlineTargetCardRequest&,
    std::uint16_t expected_calendar,const RichonlineBossCards::PreparedConsumption&);
RichonlineCombatTurnPlan prepare_richonline_combat_mine_day(const RichonlineCombatSessionView&,
    const RichonlineCombatWorld&,std::uint64_t day,bool round_anchor);
// Called only when the landing consumer will run the client's dynamic-NPC mine
// animation. It mirrors state and produces no duplicate 4017.
RichonlineCombatTurnPlan prepare_richonline_combat_stepped_mine(const RichonlineCombatSessionView&,
    const RichonlineCombatWorld&,std::int16_t root);
// The adapter MUST compare the global revision and all authoritative snapshots,
// prevalidate map/cards, then atomically commit funds/cards/status/map under the
// session lock (ledger.commit_batch can supply the funds CAS). False or throw
// must leave all stores unchanged. Only a true result permits packet broadcast
// and forwarding bankrupt_actors to the settlement coordinator. This function
// does not send wire packets or claim a callback is itself a transaction.
bool commit_richonline_combat_plan(RichonlineCombatTurnPlan&,
    const std::function<bool(const RichonlineCombatTurnPlan&)>& atomic_commit);
}
