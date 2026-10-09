#pragma once

// 游戏 TCP 监听服务：逐连接创建回调和会话，并限制准入等待时间。

#include "game_session.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <chrono>
#include <string>

namespace richnet {

struct ServiceOptions {
    std::string host = "127.0.0.1";
    std::uint16_t port = 0;
    ClientVersion version = ClientVersion::richonline;
    std::chrono::milliseconds admission_timeout{5000};
};

using LogSink = std::function<void(const std::string&)>;

class GameService final {
public:
    explicit GameService(ServiceOptions options, GameCallbackFactory factory, LogSink log = {});
    ~GameService();
    GameService(const GameService&) = delete;
    GameService& operator=(const GameService&) = delete;
    void run();
    void stop() noexcept;
    std::uint16_t bound_port() const noexcept { return bound_port_.load(); }
private:
    ServiceOptions options_;
    GameCallbackFactory factory_;
    LogSink log_;
    std::atomic_bool stopping_{false};
    std::atomic<std::uint16_t> bound_port_{0};
};
}
