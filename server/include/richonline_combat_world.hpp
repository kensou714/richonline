#pragma once
#include "richonline_combat_bridge.hpp"
#include "richonline_combat_resources.hpp"
#include "richonline_map_package.hpp"

namespace richnet {
enum class RichonlineProjectileCandidates { road_tiles,all_map_tiles };
struct RichonlineCombatRangePolicy {
    // Server authorization in tile coordinates, NOT the unsent client camera.
    std::string name;
    std::uint16_t manhattan_radius;
    RichonlineProjectileCandidates projectile_candidates;
    std::uint16_t viewport_width=0,viewport_height=0;
};
struct RichonlineCombatWorldPolicy {
    RichonlineCombatRangePolicy range;
    // 保留旧配置字段；普通装备由资源槽位及已接入效果校验，不再以此白名单拒绝时装。
    std::vector<std::uint16_t> neutral_human_equipment;
    // This names the current partial landing integration boundary. It must be
    // pure and excludes targets whose movement/landing effects are not closed.
    std::function<bool(std::int16_t,const RichonlineCombatSessionView&)> mine_landing_supported;
    // Optional extension for possession amplification/secondary/special terms.
    // Building/equipment terms are supplied by this factory exactly once.
    std::function<RichonlineCombatWorld::ResolvedTerms(const RichonlineCombatActorView&,
        const RichonlineCombatSessionView&)> extra_terms;
    std::function<RichonlineCombatCapabilities(std::uint8_t,const RichonlineActorStatus&,bool)> capabilities;
    std::function<std::optional<RichonlineBossCards::PreparedConsumption>(
        const RichonlineCombatActorView&,const RichonlineCombatSessionView&)> helmet;
    // 原客户端在4010回合入口刷新装备数值；同回合连续伤害共用该缓存。
    // 会话提供已刷新的值，建筑和状态倍率仍由战斗快照即时解析。
    std::function<RichonlineEquipmentCombatTerms(std::uint8_t)> equipment_terms{};
};
struct RichonlineCombatWorldFactoryResult {
    RichonlineCombatWorld world;
    RichonlineBossCombatPolicy boss;
    std::function<RichonlineCombatCapabilities(std::uint8_t,const RichonlineActorStatus&,bool)> capabilities;
    std::string target_policy;
};
// Base possession factors are applied once by the damage calculator.
RichonlineCombatWorld::ResolvedTerms richonline_possession_combat_terms(
    const RichonlineCombatActorView&,const RichonlineCombatSessionView&);
// Compatibility provider for callers that explicitly require no strengthening.
RichonlineCombatWorld::ResolvedTerms richonline_unamplified_possession_combat_terms(
    const RichonlineCombatActorView&,const RichonlineCombatSessionView&);
// Resource load and validation happen before room start. Human words are the
// actual profile+144 32 DWORDs sent to NEW; BOSS words come from the selected
// stage. The room continues to own topology, property, ground and actor state.
RichonlineCombatWorldFactoryResult make_richonline_combat_world(const std::filesystem::path& resources,
    const RichonlineRoadTopology&,const RichonlineBossStage&,
    const std::array<std::uint32_t,32>& human_equipment,const RichonlineMapCombatPolicy&,
    std::shared_ptr<RichonlineBossProperty>,RichonlineCombatWorldPolicy);
}
