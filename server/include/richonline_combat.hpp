#pragma once
#include "richonline_actor_status.hpp"
#include "richonline_game_ledger.hpp"
#include "richonline_boss_cards.hpp"
#include <functional>

namespace richnet {
enum class RichonlineCombatEffect { mine, missile, timed_bomb, nuclear, safe_nuclear };
struct RichonlineCombatResources {
    std::uint32_t mine_damage,timed_bomb_damage,super_mine_damage,missile_damage,nuclear_damage;
    std::uint8_t mine_days,mine_range,missile_radius,nuclear_radius,safe_nuclear_radius;
    static RichonlineCombatResources parse(std::string_view props,std::string_view npcs,std::string_view values);
    std::uint32_t base_damage(RichonlineCombatEffect) const;
};
// Supplementary values already resolved by equipment/building ownership layers.
// All fields are semantic neutral defaults, not unknown wire bytes.
struct RichonlineCombatModifiers {
    float possession_amplification=0.0F;
    float building_multiplier=1.0F;
    float secondary_status_multiplier=1.0F;
    std::int32_t equipment_percentage=0;
    float special_multiplier=1.0F;
};
std::uint32_t calculate_richonline_combat_damage(std::uint32_t base,
    const RichonlineActorStatus& attacker,const RichonlineActorStatus& defender,
    const RichonlineCombatModifiers& attacker_modifiers,const RichonlineCombatModifiers& defender_modifiers,
    bool attacker_modifiers_enabled,std::int32_t flat_attack,std::int32_t flat_defense);
enum class RichonlineExplosionTrigger { stepped_on, scheduled_expiry, missile_chain };
enum class RichonlineMineKind : std::uint8_t { normal=12,super=27 };
struct RichonlineMine {
    std::int16_t position;
    std::int8_t owner;
    std::uint8_t remaining_days;
    RichonlineMineKind kind=RichonlineMineKind::normal;
    bool red() const noexcept { return remaining_days<=1; }
    bool operator==(const RichonlineMine&) const = default;
};
struct RichonlineMineSnapshot {
    std::vector<RichonlineMine> mines;
    std::optional<std::uint64_t> last_day;
    std::uint64_t revision=0;
    bool operator==(const RichonlineMineSnapshot&) const = default;
};
struct RichonlineMineDayPlan {
    RichonlineMineSnapshot expected,after;
    std::vector<Bytes> packets;
    std::vector<RichonlineMine> expired; // Caller resolves damage before committing removal.
};
// 401E only decrements on the round anchor. No state is stored in this planner.
RichonlineMineDayPlan plan_richonline_mine_day(const RichonlineMineSnapshot&,
    std::uint64_t day,std::uint16_t game_id,bool current_actor_is_round_anchor);
RichonlineMineSnapshot plan_richonline_mine_placement(const RichonlineMineSnapshot&,
    std::int16_t position,std::int8_t owner,bool target_is_legal);
Bytes encode_richonline_mine_day401e(std::uint16_t game_id);
Bytes encode_richonline_mine_explosion4017(std::uint16_t game_id,std::int16_t position);
// Stepping and missile chains already resolve locally, so only expiry emits4017.
std::optional<Bytes> plan_richonline_mine_explosion_wire(std::uint16_t game_id,
    std::int16_t position,RichonlineExplosionTrigger);

enum class RichonlineClientDamageApplication { already_applied, by_queued_attack };
struct RichonlineCombatDamageTerms {
    std::uint32_t resource_base_damage;
    std::int32_t flat_attack,flat_defense;
    // Explicitly excludes currently unmodelled equipment/possession/building modifiers.
    bool only_shared_status_and_flat_terms;
    bool attacker_modifiers_enabled;
    std::optional<std::array<RichonlineCombatModifiers,2>> resolved_modifiers=std::nullopt;
};
struct RichonlineCombatDamagePlan {
    std::uint8_t victim;
    RichonlineGameFundsSnapshot expected;
    RichonlineGameFunds after;
    std::uint32_t damage;
    bool bankrupt;
    RichonlineClientDamageApplication client_application;
    std::optional<RichonlineBossCards::PreparedConsumption> safety_helmet_consumption;
    // Always mirror via ledger CAS: do not emit an additional cash-delta packet.
};
// Helmet availability/activation is resolved by shared cards. Caller supplies its
// prepared consumption only after validating the matching victim and Prop1076.
RichonlineCombatDamagePlan plan_richonline_combat_damage(std::uint8_t victim,
    const RichonlineGameFundsSnapshot&,RichonlineCombatEffect,
    const RichonlineActorStatus& attacker,const RichonlineActorStatus& defender,
    const RichonlineCombatDamageTerms&,RichonlineClientDamageApplication,
    std::optional<RichonlineBossCards::PreparedConsumption> safety_helmet_consumption);
// 7CBD50 normal-mine chain bonus; caller performs graph tracing before passing count.
std::uint32_t richonline_regular_mine_chain_damage(std::uint32_t single_adjusted_damage,
    std::uint32_t number_of_mines);
// NEW7CC490 counts supermine victim hits across the entire chain, not per victim.
std::uint32_t richonline_mixed_mine_chain_damage(std::uint32_t adjusted_sum,
    std::uint32_t raw_sum,std::uint32_t global_super_hits,std::uint32_t normal_base,
    std::uint32_t super_base);
bool richonline_combat_action_allowed(const RichonlineActorStatus&) noexcept;
// Shared topology adapter provides one step in a cardinal direction or nullopt.
// This records blast positions/chain mine ids only; it does not own map state.
struct RichonlineMineChainPlan {
    std::vector<std::int16_t> detonated_mines,affected_positions;
    struct Blast { RichonlineMine mine; std::vector<std::int16_t> positions; };
    std::vector<Blast> blasts; // Keep overlaps: each mine contributes separate owner-modified damage.
};
using RichonlineCombatStep=std::function<std::optional<std::int16_t>(std::int16_t,std::uint8_t)>;
RichonlineMineChainPlan plan_richonline_mine_chain(std::int16_t root,
    std::span<const RichonlineMine> mines,std::uint8_t range,const RichonlineCombatStep& step);
std::vector<std::int16_t> richonline_attack_footprint(RichonlineCombatEffect,std::int16_t target,
    std::uint16_t width,std::uint16_t height,const RichonlineCombatResources&);
bool richonline_attack_hits_actor(RichonlineCombatEffect,std::int8_t attacker,std::int8_t victim,
    bool victim_active,bool victim_in_hospital,bool victim_in_prison,bool victim_frozen);
enum class RichonlineBossBlastBuildingEffect { none,remove_ownership,lower_one_level };
// Caller normalizes2x2 building tiles through the shared map/property layer and
// applies each property once. NEW missile does not lower ordinary BOSS buildings.
RichonlineBossBlastBuildingEffect richonline_boss_blast_building_effect(RichonlineCombatEffect,
    std::int8_t building_kind,std::uint8_t level,bool owned,bool ownership_protected);
// Explicit emulator policy boss_noninventory_bank_minus_one. Does not consume hand.
Bytes encode_richonline_boss_noninventory_attack(std::uint16_t game_id,
    RichonlineCombatEffect,std::int8_t attacker,std::int16_t target,
    const RichonlineActorStatus&,bool target_within_configured_visibility);
}
