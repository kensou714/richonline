#pragma once

#include "richonline_boss_cards.hpp"
#include "richonline_boss_stage.hpp"
#include "richonline_map_rules.hpp"

#include <string_view>
#include <optional>
#include <span>

namespace richnet {
enum class RichonlineMapReadiness { partial, ready };
enum class RichonlineMapRawStatusPolicy { closed_boss_initial_status };
struct RichonlineMapChancePolicy {
    std::vector<std::int16_t> playable_reward_cards;
    bool enable_motion_status;
};
enum class RichonlineMapBadluckSelection { uniform_inventory_units_without_replacement };
struct RichonlineMapBadluckPolicy {
    std::uint8_t lost_card_limit;
    RichonlineMapBadluckSelection selection;
};
struct RichonlineMapNpcPolicy {
    std::vector<std::int8_t> god_pool;
    std::size_t initial_gods, initial_chests, minimum_objects, maximum_objects;
    std::uint64_t refresh_every_rounds;
    bool refresh_chests;
    std::array<std::int16_t,2> fortune_cards;
    std::int16_t max_transfer;
    std::optional<RichonlineMapBadluckPolicy> badluck;
};
enum class RichonlineMapProjectile { missile, nuclear, safe_nuclear };
struct RichonlineMapCombatPolicy {
    std::uint8_t attempts, idle_weight, mine_weight, projectile_weight;
    std::vector<RichonlineMapProjectile> uniform_projectiles;
    bool targets_within_visibility, allow_self_target, attacks_require_actionable_status;
    bool consume_boss_inventory;
};
struct RichonlineMapOpeningCard {
    std::int16_t card_id, count;
    bool operator==(const RichonlineMapOpeningCard&) const = default;
};
struct RichonlineMapOpeningHand {
    std::vector<RichonlineMapOpeningCard> human, boss;
};

// Immutable scenario boundary.  A package owns data proved to vary by map;
// shared transport and turn orchestration consume that data through this type.
// Do not add map-name tests to shared gameplay to represent a scenario rule.
// When a new client-proven map behavior needs a runtime operation, declare its
// typed configuration here and define it in that map's source directory.
struct RichonlineMapPackage final {
    using StageLoader = RichonlineBossStage (*)(const std::filesystem::path&, std::uint32_t);
    using PolicyFactory = RichonlineBossCardPolicy (*)(const RichonlineBossCardPolicy&);
    const std::string_view id;
    const std::string_view map_name;
    const bool special_category;
    const std::optional<std::int32_t> chance_event;
    const std::optional<std::int32_t> reward_card;
    const RichonlineMapReadiness readiness;
    const bool runtime_enabled;
    const StageLoader load_stage;
    const PolicyFactory configure;
    const std::optional<RichonlineMapChancePolicy> closed_chance;
    const std::optional<RichonlineMapNpcPolicy> closed_npcs;
    const std::optional<RichonlineMapCombatPolicy> combat;
    const std::optional<RichonlineMapOpeningHand> opening_hand;
    // Parser and board-topology contract for this exact EMP/BossWar pair.
    const RichonlineMapRuleSpecification resource_rules;
    // Explicit reachability audit: no hotel/hospital/jail/kidnap or scripted
    // NPC32 transitions are reachable from this package's implemented rules.
    const std::optional<RichonlineMapRawStatusPolicy> raw_status_policy = {};
};

const RichonlineMapPackage& find_richonline_map_package(std::string_view map_name,std::uint32_t category);
std::span<const RichonlineMapPackage* const> richonline_map_packages();
// Only the legacy global configuration schema has an implicit ordinary-map binding.
const RichonlineMapPackage& legacy_richonline_map_package();
}
