#pragma once

#include "codec.hpp"

namespace richnet {

struct OriginalCalendar {
    std::uint16_t year;
    std::uint8_t month;
    std::uint8_t day;
    std::uint8_t weekday_index;
};
struct OriginalInitPlayer {
    std::int16_t lobby_user_id;
    std::int16_t initial_tile;
    std::uint8_t direction;
    std::array<std::uint8_t, 10> skills;
    std::uint8_t opaque_last_byte;
};
struct OriginalBoardInit {
    std::uint16_t gmsv_id;
    double game_value;
    OriginalCalendar calendar;
    std::uint8_t local_slot;
    std::vector<OriginalInitPlayer> players;
    std::uint8_t opaque_header_byte;
    Bytes opaque_suffix;
};
struct OriginalFunds {
    std::uint32_t cash;
    std::uint32_t deposit;
    std::uint32_t tickets;
};
struct OriginalBoardSnapshot {
    std::uint16_t gmsv_id;
    std::uint32_t context;
    std::uint32_t scale;
    std::vector<OriginalFunds> per_player;
    Bytes opaque_suffix;
};
struct OriginalBoardEnvelope {
    std::int16_t inner_type;
    std::int8_t mode;
    std::array<std::uint8_t, 4> tail;
};
struct OriginalStartup {
    OriginalBoardInit init;
    OriginalBoardSnapshot snapshot;
    OriginalBoardEnvelope envelope;
};

Bytes encode_original_board_init(const OriginalBoardInit& init);
Bytes encode_original_board_snapshot(const OriginalBoardSnapshot& snapshot);
void validate_original_startup(const OriginalStartup& startup);
Frame original_board_frame(View plain, const OriginalBoardEnvelope& envelope, View filler);

}
