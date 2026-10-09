#pragma once

// 新版开局回调适配：衔接初始化、地图就绪、动作和轮询，显式识别已结束动作的迟到包。

#include "game_session.hpp"
#include "richonline_board.hpp"

#include <chrono>
#include <memory>
#include <optional>

namespace richnet {
struct RichonlineMapLoadPolicy {
    using Clock = std::chrono::steady_clock;
    std::chrono::milliseconds timeout;
    std::function<Clock::time_point()> now;
};
struct RichonlineStartupPlan {
    RichonlineBoardInit init;
    RichonlineBoardSnapshot snapshot;
    RichonlineBoardEnvelope envelope;
    std::function<std::vector<Bytes>()> map_ready;
    std::function<std::vector<Bytes>(const Envelope299&, View)> action;
    std::function<void()> disconnected;
    std::function<std::vector<Bytes>()> poll = {};
    // 仅当请求已完整校验、且确定属于已结束动作时返回 true。
    std::function<bool(View)> retired_action = {};
    // Transport observes this only after the exact frame was wholly sent.
    std::function<void(View)> sent = {};
    std::function<bool()> game_finished = {};
    std::function<void(const Frame&)> lobby_sent = {};
    // A committed result keeps the original lobby binding even if its game
    // transport ends during the display delay or requires outbox recovery.
    std::function<bool()> terminal_pending = {};
    // Starts at game admission; successful ready0 ends this startup-only limit.
    std::optional<RichonlineMapLoadPolicy> map_loading = {};
};
using RichonlineStartupProvider = std::function<std::optional<RichonlineStartupPlan>(const GameAdmission&)>;
using RichonlineFrameFiller = std::function<Bytes(std::size_t)>;

GameCallbacks make_richonline_game_callbacks(RichonlineStartupProvider provider,
                                             RichonlineFrameFiller filler,
                                             GameLogSink log = {});
}
