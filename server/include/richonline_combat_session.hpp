#pragma once

#include "richonline_combat.hpp"
#include "richonline_research_cards.hpp"
#include "richonline_raw_authority.hpp"
#include "richonline_building_buffs.hpp"

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
    // Snapshot of actor+1730..1737. The activation level survives upgrades and
    // mode3 ownership changes; expiry clears only the source.
    std::optional<std::uint32_t> attack_building_source,defense_building_source;
    std::uint8_t attack_building_level=0,defense_building_level=0;
    std::int8_t attack_building_rounds=0,defense_building_rounds=0;
    bool placement_present=true;
    std::optional<std::int16_t> pet_position{};
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
    std::array<std::vector<RichonlineBuildingBuffRegistration>,2> building_buff_registrations;
    std::array<std::array<bool,8>,8> building_buff_shared{};
};
RichonlineBuildingBuffState richonline_combat_building_buffs(const RichonlineCombatSessionView&);
RichonlineBuildingBuffRecipients richonline_combat_buff_recipients(const RichonlineCombatSessionView&);
void set_richonline_combat_building_buffs(RichonlineCombatSessionView&,const RichonlineBuildingBuffState&);
enum class RichonlineMissileBaseTarget : std::uint8_t { road, mine, enemy, npc };
struct RichonlineMissileBaseSalvo {
    std::uint32_t property;
    std::uint8_t owner,level,shots;
    RichonlineMissileBaseTarget target;
};
struct RichonlineMissileBaseVolley {
    RichonlineMissileBaseSalvo salvo;
    std::vector<std::int16_t> targets;
    bool controlled=false;
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
    // Detonation uses the actor-centered server viewport, independently of
    // placement eligibility. NEW sends no camera and no selected mine cell.
    std::function<std::vector<std::int16_t>(std::uint8_t,const RichonlineCombatSessionView&)> detonation_roots;
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
    // 每次攻击重读状态及建筑倍率；现金条件装备由生产会话按回合缓存，
    // 不能因同一轮已扣血而逐发改变客户端尚未刷新的装备属性。
    std::function<ResolvedTerms(const RichonlineCombatActorView&,
        const RichonlineCombatSessionView&)> resolve_terms;
    std::vector<std::int16_t> missile_base_roads;
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
    // Lua 负责 AI 类别选择；核心仍按实际状态和合法格集执行战斗事务。
    std::function<std::optional<RichonlineCombatEffect>(std::uint8_t,
        const std::function<std::size_t(std::size_t)>&)> select_attack{};
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
struct RichonlineCombatBuildingImpact {
    std::uint8_t actor;
    RichonlineCombatEffect effect;
    std::int16_t target;
    RichonlineCombatBuildingView before,after;
};
struct RichonlineCombatActorImpact {
    std::uint8_t attacker,victim;
    RichonlineCombatEffect effect;
    std::int16_t target;
    std::uint32_t cash_before,deposit_before,cash_after,deposit_after;
    std::int32_t flat_attack,flat_defense;
    bool bankrupt;
};
struct RichonlineCombatTurnPlan {
    RichonlineCombatSessionView expected,after;
    std::array<RichonlineCombatAttackAttempt,4> boss_attempts{};
    std::vector<RichonlineGameFundsUpdate> funds_updates;
    std::vector<RichonlineCombatCardConsumption> card_consumptions;
    std::vector<std::uint8_t> bankrupt_actors;
    std::vector<Bytes> packets;
    bool committed=false;
    std::vector<RichonlineMissileBaseVolley> base_volleys;
    // 逐次保留命中结果，含被 LAND 保护的空地；只有事务提交后才输出日志。
    std::vector<RichonlineCombatBuildingImpact> building_impacts;
    std::vector<RichonlineCombatActorImpact> actor_impacts;
};
RichonlineCombatTurnPlan prepare_richonline_missile_base_round(const RichonlineCombatSessionView&,
    const RichonlineCombatWorld&,std::span<const RichonlineMissileBaseSalvo>,
    const std::function<std::size_t(std::size_t)>& random);
RichonlineCombatTurnPlan prepare_richonline_boss_combat_turn(const RichonlineCombatSessionView&,
    const RichonlineCombatWorld&,std::uint8_t boss,const RichonlineBossAttackRandomness&,
    const RichonlineBossCombatPolicy& = {});
RichonlineCombatTurnPlan prepare_richonline_combat_human_card(const RichonlineCombatSessionView&,
    const RichonlineCombatWorld&,std::uint8_t actor,const RichonlineTargetCardRequest&,
    std::uint16_t expected_calendar,const RichonlineBossCards::PreparedConsumption&);
RichonlineCombatTurnPlan prepare_richonline_combat_mine_day(const RichonlineCombatSessionView&,
    const RichonlineCombatWorld&,std::uint64_t day,bool round_anchor);
RichonlineCombatTurnPlan prepare_richonline_combat_detonate(const RichonlineCombatSessionView&,
    const RichonlineCombatWorld&,std::uint8_t actor,const RichonlineBossCards::PreparedConsumption&);
// Ordinary landings already run the client's mine animation. Relocation callers
// request4017 explicitly because their position update skips the landing phase.
RichonlineCombatTurnPlan prepare_richonline_combat_stepped_mine(const RichonlineCombatSessionView&,
    const RichonlineCombatWorld&,std::int16_t root,bool notify_client=false);
// NEW7CC970: one landing victim, shared7CE420 modifiers, no helmet or mine immunity,
// no removal of NPC26 and no additional wire effect.
RichonlineCombatTurnPlan prepare_richonline_combat_fire_landing(const RichonlineCombatSessionView&,
    const RichonlineCombatWorld&,std::int8_t owner,std::uint8_t victim,std::int16_t position,
    std::uint32_t npc26_damage);
struct RichonlineCombatPoisonPlan {
    RichonlineCombatTurnPlan combat;
    std::uint32_t after_use_count;
    std::vector<std::uint8_t> hit_actors;
};
RichonlineCombatPoisonPlan prepare_richonline_combat_poison(const RichonlineCombatSessionView&,
    const RichonlineCombatWorld&,const RichonlineResearchCardRequest&,const RichonlineResearchCardContext&,
    std::uint32_t use_count,const RichonlinePoisonRules&,std::span<const RichonlinePoisonCell>,
    std::span<const RichonlineRawActorState>);
// The adapter MUST compare the global revision and all authoritative snapshots,
// prevalidate map/cards, then atomically commit funds/cards/status/map under the
// session lock (ledger.commit_batch can supply the funds CAS). False or throw
// must leave all stores unchanged. Only a true result permits packet broadcast
// and forwarding bankrupt_actors to the settlement coordinator. This function
// does not send wire packets or claim a callback is itself a transaction.
bool commit_richonline_combat_plan(RichonlineCombatTurnPlan&,
    const std::function<bool(const RichonlineCombatTurnPlan&)>& atomic_commit);
}
