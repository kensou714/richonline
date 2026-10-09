#pragma once

// 新版 BOSS 运行时入口：从持久层与启动资源装配可选的大厅游戏提供器。

#include "lobby_runtime.hpp"

namespace richnet {
std::optional<RichonlineRuntimeGame> load_richonline_boss_runtime(
    Storage& storage, const std::filesystem::path& bootstrap, ControlLog log);
}
