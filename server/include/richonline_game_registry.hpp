#pragma once

// 新版游戏登记：按频道和房间维护开局计划、准入有效期及连接回调。

#include "game_session.hpp"
#include "pending_game_admissions.hpp"
#include "richonline_game_redirect.hpp"
#include "richonline_room_directory.hpp"

#include <memory>

namespace richnet {
struct RichonlineGamePlan {
    std::uint64_t connection;
    std::uint32_t actor;
    RichonlineGameRedirect redirect;
    std::function<std::vector<Frame>()> admitted;
    std::function<std::vector<Frame>(const Envelope299&, View)> message;
    std::function<void()> disconnected;
    std::function<std::vector<Frame>()> poll = {};
    std::function<void(const Frame&)> sent = {};
    // True while all game result frames are sent and the final lobby 58 is ready to send.
    std::function<bool()> game_finished = {};
    // Exact final-58 confirmation must make game_finished false; ignored bytes leave it true.
    std::function<void(const Frame&)> lobby_sent = {};
    // Keeps the original lobby binding while results deliver, wait for presentation, or require recovery.
    std::function<bool()> terminal_pending = {};
    // Optional hook after exact lobby-58 whole-send confirmation and retirement
    // check, outside the gate. Exceptions propagate; the durable intent remains.
    std::function<void()> profile_refresh_ready = {};
};
using RichonlineGameProvider = std::function<std::vector<RichonlineGamePlan>(const RichonlineRoomSnapshot&)>;
using RichonlineGameClock = std::function<AdmissionClock::time_point()>;

class RichonlineGameRegistry final {
public:
    RichonlineGameRegistry(RichonlineGameProvider provider, std::uint32_t manager,
                           std::chrono::milliseconds admission_ttl, RichonlineGameClock clock = AdmissionClock::now);
    std::vector<RichonlineRoomDispatch> prepare(const RichonlineRoomSnapshot& room);
    void cancel_room(std::uint32_t channel, std::uint32_t room_key);
    bool has_room(std::uint32_t channel, std::uint32_t room_key);
    bool completed_room(std::uint32_t channel, std::uint32_t room_key);
    // Returns true only when this participant's exact final 58 advanced its terminal coordinator.
    bool notify_lobby_sent(std::uint64_t lobby_connection,const Frame& frame);
    // 此重载仅供单频道调用方；正式大厅分派必须同时提供频道和房间标识。
    void cancel_room(std::uint32_t room_key);
    bool has_room(std::uint32_t room_key);
    void shutdown();
    GameCallbacks callbacks();
private:
    struct State;
    std::shared_ptr<State> state_;
};
}
