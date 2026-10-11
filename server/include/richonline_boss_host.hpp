#pragma once

// 新版 BOSS 宿主装配：读取启动配置，并允许注入开局策略提供器。

#include "lobby_runtime.hpp"
#include "richonline_boss_startup.hpp"
#include "richonline_game_startup.hpp"
#include "richonline_classic_startup.hpp"

namespace richnet {
using RichonlineBossStrategyFactory = std::function<RichonlineStartupPlan(const RichonlineBossStartup&)>;
// 必须返回与startup.recipients同序的共享会话计划，使用shared_startups协调全员收发。
// 生产端未提供完整经典玩法工厂时，mode0仍明确拒绝，不发送半成品棋盘。
struct RichonlineClassicHostStrategy {
    RichonlineMapSpawnPolicy spawn_policy;
    std::function<std::vector<RichonlineStartupPlan>(const RichonlineClassicStartup&,RichonlineBoardEnvelope)> create;
};

std::optional<RichonlineRuntimeGame> load_richonline_boss_host(
    Storage& storage, const std::filesystem::path& bootstrap, ControlLog log,
    RichonlineBossStrategyFactory strategy = {},std::optional<RichonlineClassicHostStrategy> classic = {});
}
