#pragma once

// 大厅运行时装配：分别接入新版与旧版游戏提供器，向管理端提供状态和停止入口。

#include "control.hpp"
#include "storage.hpp"
#include "richonline_game_registry.hpp"
#include "original_game_host.hpp"
#include <memory>

namespace richnet {
struct RichonlineRuntimeGame {
    std::uint16_t port;
    std::uint32_t manager;
    std::chrono::milliseconds admission_ttl;
    std::function<std::vector<RichonlineGamePlan>(std::uint16_t, const RichonlineRoomSnapshot&)> provider;
};
struct OriginalRuntimeGame {
    std::uint16_t port;
    std::array<std::uint8_t,4> advertised_address;
    std::chrono::milliseconds admission_ttl;
    OriginalRoomGameProvider provider;
};
class LobbyRuntime final {
public:
    LobbyRuntime(Storage& storage, const std::filesystem::path& bootstrap, const ControlLog& log,
                 std::optional<RichonlineRuntimeGame> game = {}, std::optional<OriginalRuntimeGame> original_game = {});
    ~LobbyRuntime();
    LobbyRuntime(const LobbyRuntime&) = delete;
    LobbyRuntime& operator=(const LobbyRuntime&) = delete;
    nlohmann::json status() const;
    void stop() noexcept;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
