#pragma once

#include "game_session.hpp"
#include "original_board.hpp"

namespace richnet {
struct OriginalGamePlan {
    OriginalStartup startup;
    std::function<std::vector<Bytes>()> map_ready;
    std::function<std::vector<Bytes>(View)> action;
    std::function<void()> disconnected;
    std::function<std::vector<Bytes>()> poll = {};
    std::function<std::optional<std::uint16_t>()> closed_shop_context = {};
    std::function<bool(View)> expired_shop_action = {};
};
using OriginalGameAdmissionProvider = std::function<std::optional<OriginalGamePlan>(const GameAdmission&)>;

GameCallbacks make_original_game_callbacks(OriginalGameAdmissionProvider provider, GameLogSink log = {});
}
