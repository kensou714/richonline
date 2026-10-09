#pragma once
#include "original_room_description.hpp"
#include "original_game_startup.hpp"

namespace richnet {
struct OriginalRoomPlayer { std::uint32_t user_id, slot, team; Bytes profile; };
struct OriginalRoomSnapshot {
    std::uint64_t generation;
    std::uint32_t channel_id, game_id, owner;
    OriginalGameDescription description;
    std::vector<OriginalRoomPlayer> players;
};
struct OriginalRoomRedirect { std::uint32_t user_id; Frame message; };
struct OriginalGamePlanForUser { std::uint32_t user_id; OriginalGamePlan plan; };
}
