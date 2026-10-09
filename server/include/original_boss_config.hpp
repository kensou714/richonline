#pragma once

#include "original_board.hpp"

#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>

namespace richnet {

enum class OriginalBossSupport { implemented, map_unsupported };
struct OriginalBossAttackPolicy {
    std::uint8_t attempts;
    std::uint8_t idle_weight;
    std::uint8_t mine_weight;
    std::uint8_t weapon_weight;
    std::vector<std::int16_t> weapon_pool;
};
struct OriginalBossStageValues {
    OriginalFunds human;
    OriginalFunds boss;
    std::vector<std::int16_t> human_initial_cards;
    std::uint8_t max_building_skills;
    OriginalBossAttackPolicy attack;
};
struct OriginalBossStage {
    std::string stage_id;
    std::string map_name;
    std::string name;
    bool enabled;
    OriginalBossSupport support_status;
    std::optional<std::uint32_t> human_cash, human_deposit, boss_cash, boss_deposit;
    std::optional<std::uint32_t> human_tickets, boss_tickets;
    std::optional<std::vector<std::int16_t>> human_initial_cards;
    std::optional<std::uint8_t> max_building_skills;
    OriginalBossAttackPolicy attack;
};
class OriginalBossConfig final {
public:
    static OriginalBossConfig parse(std::string_view text, const std::set<std::int16_t>& known_card_ids);
    static OriginalBossConfig load(const std::filesystem::path& path, const std::set<std::int16_t>& known_card_ids);
    const std::map<std::string, OriginalBossStage>& stages() const noexcept { return stages_; }
    OriginalBossStageValues playable(std::string_view stage_id) const;
private:
    std::map<std::string, OriginalBossStage> stages_;
};

}
