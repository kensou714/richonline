#pragma once

// 新版棋盘启动协议：玩家记录、资金快照与无尾部的 299 包装；opaque 字段不推测语义。

#include "codec.hpp"

namespace richnet {
struct RichonlineBoardParticipant {
    std::int16_t lobby_identity;
    std::int16_t position;
    std::uint8_t direction;
    std::array<std::int8_t, 10> building_skill_caps;
    std::uint8_t opaque_trailing;
};
struct RichonlineBoardInit {
    std::uint16_t game_server_id;
    std::array<std::uint8_t, 8> opaque_f64;
    std::int16_t year;
    std::uint8_t month;
    std::uint8_t day;
    std::uint8_t weekday;
    std::uint8_t local_slot;
    std::uint8_t opaque_header_byte;
    std::vector<RichonlineBoardParticipant> participants;
};
struct RichonlineBoardBalances {
    std::uint32_t cash;
    std::uint32_t deposit;
    std::uint32_t tickets;
};
struct RichonlineBoardSnapshot {
    std::uint16_t game_server_id;
    std::uint32_t calendar_counter;
    std::uint32_t monetary_scale;
    std::vector<RichonlineBoardBalances> slots;
};
struct RichonlineBoardEnvelope {
    std::int16_t tag;
    std::int8_t mode;
};

Bytes encode_richonline_board_init(const RichonlineBoardInit& init);
Bytes encode_richonline_board_snapshot(const RichonlineBoardSnapshot& snapshot);
Frame richonline_board_frame(View plain, RichonlineBoardEnvelope envelope, View filler);
}
