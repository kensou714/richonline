#pragma once

// 新版 BOSS 落点处理：限定空状态落点支持范围，并显式提交点数变化。

#include "richonline_boss_turns.hpp"
#include "richonline_game_ledger.hpp"

namespace richnet {
inline bool richonline_landing_controlled(const RichonlineActorStatus& status) noexcept {
    return status.possession==7 || status.sleepwalking!=0 || status.frozen!=0;
}
// 新闻属于服务端事件：BOSS 梦游仍触发三色新闻；其他角色及控制状态沿用原限制。
inline bool richonline_news_landing_allowed(const RichonlineLandingContext& context) noexcept {
    const auto& status=context.actor_status;
    return context.game_mode==3 && context.static_type>=68 && context.static_type<=70 &&
        status.possession!=7 && !status.frozen && (!status.sleepwalking || context.synthetic_actor);
}
// 动态地面效果和碰撞之后检查静态格跳过规则；梦游 BOSS 新闻交给新闻事务。
// 地产收费和地面 NPC 效果不在此处跳过。
std::optional<RichonlineLandingResult> resolve_richonline_controlled_static_landing(
    std::uint16_t game_server_id,const RichonlineLandingContext& context);
// 仅供空状态引擎：无动态物件、状态、倒计时、途经效果或待处理回调；不能通用跳过格子事件。
// 输出 4013 已确认读取/重放的 6 字节前缀，不据此断言历史完整包长。
// 合成 BOSS 的商店采用无卡包规则：4031(-1) 结束访问。
RichonlineLandingResult resolve_richonline_empty_boss_landing(std::uint16_t game_server_id,
    const RichonlineLandingContext& context);
struct RichonlineTicketLandingPlan {
    RichonlineGameFundsUpdate funds;
    RichonlineLandingResult result;
};
// 仅准备5/6/7点券格。Lua指定增量；省略时供原生回退使用。
// 金额必须匹配客户端4013后自算的规则，准备过程不改账本。
RichonlineTicketLandingPlan prepare_richonline_ticket_landing(std::uint16_t game_id,
    const RichonlineLandingContext& context,const RichonlineGameFundsSnapshot& funds,
    std::optional<std::uint32_t> reward={});
class RichonlineBossLandingState final {
public:
    RichonlineBossLandingState(std::uint16_t game_id,std::array<std::uint32_t,2> points);
    RichonlineBossLandingState(std::uint16_t game_id,std::shared_ptr<RichonlineGameLedger> ledger);
    void validate_landing(const RichonlineLandingContext& context) const;
    RichonlineLandingResult land(const RichonlineLandingContext& context);
    std::array<std::uint32_t,2> points() const;
    void commit_points(std::uint8_t actor,std::uint32_t expected,std::uint32_t updated);
private:
    std::uint16_t game_id_;
    std::shared_ptr<RichonlineGameLedger> ledger_;
};
}
