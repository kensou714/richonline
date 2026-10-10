#pragma once

#include "richonline_combat_resources.hpp"
#include <optional>
#include <span>
#include <vector>

namespace richnet {
enum class RichonlineBuildingBuffKind { defense, attack };
struct RichonlineBuildingBuffRegistration {
    std::int16_t property=-1;
    std::int8_t rounds=0;
    bool operator==(const RichonlineBuildingBuffRegistration&) const = default;
};
struct RichonlineActiveBuildingBuff {
    std::optional<std::int16_t> property;
    std::uint8_t level=0;
    std::int8_t rounds=0;
    bool operator==(const RichonlineActiveBuildingBuff&) const = default;
};
struct RichonlineBuildingBuffState {
    // Native map tables have one slot per EMP property, independently per kind.
    std::array<std::vector<RichonlineBuildingBuffRegistration>,2> registrations;
    std::array<std::vector<RichonlineActiveBuildingBuff>,2> actors;
    bool operator==(const RichonlineBuildingBuffState&) const = default;
};
struct RichonlineBuildingBuffProperty {
    std::int16_t property;
    std::optional<std::uint8_t> owner;
    std::uint8_t level;
    std::int8_t kind=-1;
};
struct RichonlineBuildingBuffRecipients {
    std::vector<bool> active;
    // Owner's actor+1480 relation, not the alliance card's actor+1472 countdown.
    std::vector<std::vector<bool>> shared;
};
struct RichonlineBuildingBuffActivation {
    RichonlineBuildingBuffKind kind;
    std::int16_t property;
    std::uint8_t owner,level;
};
struct RichonlineBuildingBuffRound {
    RichonlineBuildingBuffState after;
    std::vector<RichonlineBuildingBuffActivation> activations;
};
enum class RichonlineBuildingBuffChangeKind {
    construction, ownership, conversion, blast_downgrade
};
struct RichonlineBuildingBuffChange {
    RichonlineBuildingBuffChangeKind kind;
    RichonlineBuildingBuffProperty before,after;
};
RichonlineBuildingBuffState make_richonline_building_buff_state(std::size_t property_count,std::size_t actor_count);
// No allocation or deduplication: first free slot, or false when native table is full.
bool register_richonline_building_buff(RichonlineBuildingBuffState&,RichonlineBuildingBuffKind,std::int16_t property);
// Removes only the first matching production slot. Active buffs have a separate lifecycle.
bool unregister_richonline_building_buff(RichonlineBuildingBuffState&,RichonlineBuildingBuffKind,std::int16_t property);
// Mode3 lifecycle, in client event order. Ownership changes preserve old slots
// and active buffs; conversion/blasts use the first active source holder.
// A building swap supplies two ownership events, source first, after the swap.
RichonlineBuildingBuffState plan_richonline_building_buff_changes(const RichonlineBuildingBuffState&,
    std::span<const RichonlineBuildingBuffChange>,const RichonlineBuildingBuffRecipients&);
// Pure round plan: defense expiry/production, then attack expiry/production.
// Caller commits it with the property's revision and actor snapshot before sending continuation.
RichonlineBuildingBuffRound plan_richonline_building_buff_round(const RichonlineBuildingBuffState&,
    std::span<const RichonlineBuildingBuffProperty>,const RichonlineBuildingBuffRecipients&,
    const RichonlineCombatModifierResources&);
}
