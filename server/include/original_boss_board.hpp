#pragma once
#include "original_boss_config.hpp"
#include "original_map.hpp"
#include "original_room_description.hpp"

namespace richnet {
struct OriginalBossSpawn {
    std::int16_t tile;
    std::uint8_t direction;
};
struct OriginalBossBoardRequest {
    OriginalGameDescription room;
    std::int16_t human_user_id;
    OriginalBossSpawn human_spawn, boss_spawn;
    std::uint16_t instance;
    std::uint32_t context;
    OriginalCalendar calendar;
    double game_value;
    std::array<std::uint8_t,10> boss_record_skills;
    std::uint8_t header_alignment, human_alignment, boss_alignment;
    Bytes init_suffix, snapshot_suffix;
    OriginalBoardEnvelope envelope;
};
struct OriginalBossBoard {
    OriginalMapResources map;
    OriginalBossStageValues settings;
    OriginalStartup startup;
};
OriginalBossBoard prepare_original_boss_board(OriginalMapResources map,
    const OriginalBossConfig& config, const OriginalBossBoardRequest& request);
}
