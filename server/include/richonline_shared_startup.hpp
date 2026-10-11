#pragma once

#include "richonline_game_startup.hpp"

namespace richnet {
struct RichonlineSharedMessage {
    // 空值表示广播给仍连接的真人；有值表示该局内角色的私有消息。
    std::optional<std::uint8_t> recipient;
    Bytes plain;
};
using RichonlineSharedMessages=std::vector<RichonlineSharedMessage>;
struct RichonlineSharedCallbacks {
    std::function<RichonlineSharedMessages()> opening;
    std::function<RichonlineSharedMessages(std::uint8_t,const Envelope299&,View)> action;
    std::function<void(std::uint8_t)> disconnected;
    std::function<RichonlineSharedMessages()> poll = {};
    std::function<RichonlineSharedMessages(std::uint8_t,const RichonlineStockRequest&)> stock_action = {};
    std::function<bool(std::uint8_t,View)> retired_action = {};
    std::function<void(std::uint8_t,View)> sent = {};
    std::function<bool(std::uint8_t)> game_finished = {};
    std::function<void(std::uint8_t,const Frame&)> lobby_sent = {};
    std::function<bool(std::uint8_t)> terminal_pending = {};
};
// 每个真人一份4000，只有local_slot不同，4004相同。返回顺序与inits相同。
// 回调在整局互斥锁内执行，不得反调本适配器。业务仍负责回合、库存、资产和结算。
// 全员快照完整发送后只开局一次；每批消息全员发完再处理下一操作。
// 不去重相同请求字节：股票窗口允许连续多次相同买卖，重放判定属于具体业务。
std::vector<RichonlineStartupPlan> make_richonline_shared_startups(
    std::vector<RichonlineBoardInit> inits,RichonlineBoardSnapshot snapshot,
    RichonlineBoardEnvelope envelope,RichonlineSharedCallbacks callbacks,
    RichonlineMapLoadPolicy loading);
}
