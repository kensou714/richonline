#pragma once

// 新版 BOSS 棋盘初始化：组合房间与玩家资料，保留显式提供的未确认字节。

#include "richonline_board.hpp"
#include "richonline_room_directory.hpp"

#include <filesystem>

namespace richnet {
struct RichonlineBossWirePolicy {
    std::uint16_t game_server_id;
    std::uint32_t calendar_counter;
    std::int16_t year;
    std::uint8_t month, day, weekday;
    std::array<std::uint8_t, 8> opaque_f64;
    std::uint8_t opaque_header_byte;
    std::array<std::uint8_t, 2> opaque_trailing;
    std::array<std::int8_t, 10> synthetic_unconsumed_skill_bytes;
    RichonlineBoardEnvelope envelope;
};
struct RichonlineBossStartupInput {
    std::int16_t human_identity;
    // 原样复制玩家资料偏移 +144..271 的 DWORD，包含已装备槽位。
    std::array<std::uint32_t, 32> profile_slots;
    std::array<std::int8_t, 10> building_skill_caps;
    RichonlineBossWirePolicy wire;
};
struct RichonlineBossStartup {
    RichonlineRoomSnapshot room;
    RichonlineBoardInit init;
    RichonlineBoardSnapshot snapshot;
    RichonlineBoardEnvelope envelope;
    // Preserve the actual validated equipment sent in the room profile. The
    // combat factory must not reread a potentially changed account snapshot.
    std::optional<std::array<std::uint32_t,32>> human_profile_slots = {};
};

// 仅构造初始化数据，不提供地图就绪或游戏动作回调。
RichonlineBossStartup build_richonline_boss_startup(const std::filesystem::path& client_root,
    const RichonlineRoomSnapshot& room, const RichonlineBossStartupInput& input);
}
