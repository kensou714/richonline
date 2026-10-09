#pragma once

// 单条游戏连接状态机：先校验准入，再分派 299 消息，并编码回包与轮询结果。

#include "game_admission.hpp"

#include <functional>
#include <string>
#include <deque>

namespace richnet {

struct GameCallbacks {
    // 所属大厅必须核验当前版本的完整准入描述，不能只比较部分身份字段。
    std::function<bool(const GameAdmission&)> authorize_admission;
    std::function<std::vector<Frame>(const GameAdmission&)> admitted;
    std::function<std::vector<Frame>(const GameAdmission&, const Envelope299&, View)> message;
    std::function<void(const GameAdmission&)> disconnected;
    std::function<std::vector<Frame>(const GameAdmission&)> poll = {};
    // Transport notification only after this entire encoded frame was accepted by send().
    std::function<void(const GameAdmission&, const Frame&)> sent = {};
    // A registry may select an observed plan only after admission; absent means sent is enabled.
    std::function<bool(const GameAdmission&)> sent_enabled = {};
};

using GameCallbackFactory = std::function<GameCallbacks()>;
using GameLogSink = std::function<void(const std::string&)>;
// departing holds a successfully encoded leave response until the transport
// sends it. finish() then releases admission/room state exactly once.
enum class GameState { awaiting_admission, admitted, departing, closed };

class GameSession final {
public:
    GameSession(ClientVersion version, GameCallbacks callbacks, GameLogSink log = {});
    ~GameSession();
    GameSession(const GameSession&) = delete;
    GameSession& operator=(const GameSession&) = delete;
    std::vector<Bytes> feed(View chunk);
    std::vector<Bytes> poll();
    void sent(View encoded_frame);
    void finish();
    GameState state() const noexcept { return state_; }
private:
    std::vector<Frame> receive(const Frame& frame);
    void encode(const std::vector<Frame>& frames, std::vector<Bytes>& output);
    void close() noexcept;
    ClientVersion version_;
    GameCallbacks callbacks_;
    GameLogSink log_;
    StreamDecoder decoder_;
    GameState state_ = GameState::awaiting_admission;
    std::optional<GameAdmission> admission_;
    bool finished_ = false;
    struct PendingSend { Bytes wire; Frame frame; };
    std::deque<PendingSend> pending_sends_;
};

}
