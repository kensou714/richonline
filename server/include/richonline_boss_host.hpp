#pragma once

// 新版 BOSS 宿主装配：读取启动配置，并允许注入开局策略提供器。

#include "lobby_runtime.hpp"
#include "richonline_boss_startup.hpp"
#include "richonline_game_startup.hpp"
#include "richonline_classic_startup.hpp"
#include "richonline_shared_startup.hpp"

namespace richnet {
using RichonlineBossStrategyFactory = std::function<RichonlineStartupPlan(const RichonlineBossStartup&)>;
// 业务只返回一份整局回调，宿主统一创建shared_startups并协调全员收发与移动上报。
// 生产端未提供完整经典玩法工厂时，mode0仍明确拒绝，不发送半成品棋盘。
struct RichonlineClassicHostStrategy {
    RichonlineMapSpawnPolicy spawn_policy;
    RichonlineMapLoadPolicy loading;
    std::function<RichonlineSharedCallbacks(const RichonlineClassicStartup&,RichonlineBoardEnvelope)> create;
};

std::optional<RichonlineRuntimeGame> load_richonline_boss_host(
    Storage& storage, const std::filesystem::path& bootstrap, ControlLog log,
    RichonlineBossStrategyFactory strategy = {},std::optional<RichonlineClassicHostStrategy> classic = {});
}
