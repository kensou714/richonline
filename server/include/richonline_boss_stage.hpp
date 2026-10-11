#pragma once

// 新版 BOSS 关卡资源：读取地图、初始资金、装备、建筑能力与场景限制。

#include "original_map.hpp"
#include <string_view>

namespace richnet {
struct RichonlineStageFunds {
    std::uint32_t cash, deposit, tickets;
};
struct RichonlineStageBoss {
    std::uint32_t count, base_cash, max_dice, mood;
    std::int32_t role;
    std::array<std::uint32_t,12> equipment;
    std::array<std::uint8_t,10> building_skills;
};
struct RichonlineStageReward {
    std::uint32_t experience, gold, item_count;
    std::vector<std::int32_t> item_ids;
};
enum class RichonlineBossDropKind { active_item, inactive_item, skill };
struct RichonlineBossDrop {
    RichonlineBossDropKind kind;
    // 物品使用 Prop 编号；技能使用 Yan..Shou 的 0..9 索引。
    std::uint16_t id;
    std::uint8_t level;
    std::uint32_t weight;
    bool operator==(const RichonlineBossDrop&) const = default;
};
inline constexpr std::array<std::string_view,12> richonline_boss_equipment_keys{
    "bossPet","bossVehicle","bossLand","bossDeng","bossDice","bossMove",
    "bossSuit","bossGlass","bossCover","bossMask","bossKitbag","bossGowith"};
inline constexpr std::array<std::string_view,10> richonline_building_keys{
    "Yan","Pao","Chang","Zhong","Kong","Mi","Ba","Shan","Zhao","Shou"};
struct RichonlineBossStage {
    std::string map_name;
    std::uint32_t map_id, mode, width, height;
    std::array<std::uint8_t,16> signature;
    RichonlineStageFunds human;
    std::uint32_t monetary_scale, wait_seconds, game_months, pawn_gold, player_selection;
    std::vector<std::uint32_t> player_count_choices;
    RichonlineStageBoss boss;
    std::uint8_t default_building_kind;
    std::array<std::uint8_t,10> scenario_caps;
    std::uint32_t category;
    RichonlineStageReward first_reward, repeat_reward;
    // Absent keys stay absent. Static67 consumers must not invent a fee/reward.
    std::optional<std::uint32_t> invest_base, invest_return;
    std::vector<RichonlineBossDrop> chest_drops;
};

RichonlineBossStage parse_richonline_boss_stage(std::string_view bosswar_text,
    std::string_view map_name, const OriginalEmp& map,std::uint32_t category=0);
RichonlineBossStage load_richonline_boss_stage(const std::filesystem::path& client_root,
    std::string_view map_name,std::uint32_t category=0);
}
