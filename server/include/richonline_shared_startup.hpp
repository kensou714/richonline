#pragma once

#include "richonline_game_startup.hpp"

namespace richnet {
struct RichonlineSharedMessage {
    // 空值表示广播给仍连接的真人；有值表示该局内角色的私有消息。
    std::optional<std::uint8_t> recipient;
    Bytes plain;
};
using RichonlineSharedMessages=std::vector<RichonlineSharedMessage>;
struct RichonlineSharedMovementWait {
    // 对局业务提供严格递增的移动序号，不用会回绕的日历WORD充当唯一编号。
    std::uint64_t sequence;
    std::uint16_t calendar;
    std::int16_t endpoint;
    // 齐备后提交此真人连接实际送来的请求；合成角色可由其控制连接报告。
    std::uint8_t controller;
    // 只允许已核实为各客户端共同上报的0011末端和0028途中银行暂停。
    std::uint16_t opcode=0x11;
    bool operator==(const RichonlineSharedMovementWait&) const = default;
};
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
    // 0011末端与0028银行暂停会由各客户端的公共移动动画产生；业务公布真实待决
    // 操作码/位置后，共享层等待全体连接一致，再把控制连接的请求交给action一次。
    // 完成或取消后返回空值；新的移动必须使用更大sequence。回调不得重入共享层。
    std::function<std::optional<RichonlineSharedMovementWait>()> movement_wait = {};
    // 全员完整收到当前批消息后开始计时。缺失上报时使整局失败，不伪造完成或推进回合。
    std::chrono::milliseconds movement_timeout{30000};
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
