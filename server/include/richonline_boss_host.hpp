#pragma once

// 新版 BOSS 宿主装配：读取启动配置，并允许注入开局策略提供器。

#include "lobby_runtime.hpp"
#include "richonline_boss_startup.hpp"
#include "richonline_game_startup.hpp"

namespace richnet {
using RichonlineBossStrategyFactory = std::function<RichonlineStartupPlan(const RichonlineBossStartup&)>;

std::optional<RichonlineRuntimeGame> load_richonline_boss_host(
    Storage& storage, const std::filesystem::path& bootstrap, ControlLog log,
    RichonlineBossStrategyFactory strategy = {});
}
