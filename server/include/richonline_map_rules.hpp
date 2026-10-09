#pragma once

#include "richonline_boss_stage.hpp"
#include "richonline_property_resources.hpp"
#include "richonline_route.hpp"
#include <map>
#include <span>

namespace richnet {
struct RichonlineMapPackage;
enum class RichonlineMapSpawnPolicy {
    all_candidates_connected,
    largest_adjacent_component
};
// Per-map resource boundary, kept beside that map's package descriptor.
struct RichonlineMapRuleSpecification {
    std::vector<std::int8_t> expected_static_types;
    RichonlineMapSpawnPolicy spawn_policy=RichonlineMapSpawnPolicy::all_candidates_connected;
};
enum class RichonlineMapStaticEffect {
    none, tickets, card_reward, pending_server_reward, chance_event, shop, paired_portal,
    local_vendor, unsupported
};
struct RichonlineMapStaticRule {
    RichonlineMapStaticEffect effect;
    bool human_waits_for_server;
    bool synthetic_waits_for_server;
    bool has_property_phase;
};
// Client phase1 and phase2 are independent. Property routing is determined by
// the actual road reference, never by an ordinary-map static-type range.
RichonlineMapStaticRule richonline_map_static_rule(const RichonlineRoadCell& cell);

struct RichonlineMapSpawnChoice {
    std::int16_t position;
    std::uint8_t direction;
    bool operator==(const RichonlineMapSpawnChoice&) const = default;
};
struct RichonlineMapInitialNpc {
    std::int16_t position;
    std::int8_t type, owner, lifetime;
    // NEW7DF010 preserves this second source DWORD but does not read it when
    // inserting the ground NPC. Keep its bits, without inventing a meaning.
    std::uint32_t unconsumed_source_value;
};
struct RichonlineMapRuleResources {
    RichonlineBossStage stage;
    RichonlineRoadTopology topology;
    RichonlinePropertyResources properties;
    std::map<std::int8_t,std::size_t> static_counts,terrain_counts;
    std::array<std::optional<std::array<std::int16_t,2>>,2> portals; // types28/61
    std::vector<RichonlineMapInitialNpc> initial_npcs;
    std::vector<std::uint32_t> source_dword_array;
    std::vector<OriginalCardWeight> card_weights;
    std::vector<std::int16_t> pool_a_ids,pool_b_ids;
    // NEW7DF010 counted DWORD arrays copied to members44 and34. Their
    // gameplay meaning has not been established; preserve exact source bits.
    std::array<std::vector<std::uint32_t>,2> source_extra_arrays;
    // Entire120-byte fixed tail header, including the six DWORDs after the
    // paired portal coordinates. No source field is filled with placeholders.
    std::array<std::int32_t,30> source_prelude;
    std::array<std::int32_t,11> source_postlude;
    std::size_t parsed_tail_bytes;
    // Explicit package-selected native graph policy, not historical spawn data.
    std::optional<std::array<RichonlineMapSpawnChoice,2>> conservative_spawns;
    std::optional<std::string> conservative_spawn_error;
};
RichonlineMapRuleResources load_richonline_map_rule_resources(
    const std::filesystem::path& root,const RichonlineMapPackage& package,
    std::uint32_t category);
RichonlineMapRuleResources richonline_map_rule_resources(
    const RichonlineBossStage& stage,const OriginalEmp& emp,
    const RichonlineMapRuleSpecification& specification,std::int32_t price_base);
std::array<RichonlineMapSpawnChoice,2> choose_richonline_map_conservative_spawns(
    const RichonlineRoadTopology& topology);
std::array<RichonlineMapSpawnChoice,2> choose_richonline_map_spawns(
    const RichonlineRoadTopology& topology,RichonlineMapSpawnPolicy policy);
}
