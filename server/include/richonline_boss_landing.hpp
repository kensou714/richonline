#pragma once

// 新版 BOSS 落点处理：限定空状态落点支持范围，并显式提交点数变化。

#include "richonline_boss_turns.hpp"
#include "richonline_game_ledger.hpp"

namespace richnet {
inline bool richonline_landing_controlled(const RichonlineActorStatus& status) noexcept {
    return status.possession==7 || status.sleepwalking!=0 || status.frozen!=0;
}
// NEW7C54B0 skips only special road events under these control states. Call
// after dynamic ground effects and collision resolution, before bank/chance/
// shop admission. Property charging and ground NPC effects are not skipped.
std::optional<RichonlineLandingResult> resolve_richonline_controlled_static_landing(
    std::uint16_t game_server_id,const RichonlineLandingContext& context);
// 仅供空状态引擎：无动态物件、状态、倒计时、途经效果或待处理回调；不能通用跳过格子事件。
// 输出 4013 已确认读取/重放的 6 字节前缀，不据此断言历史完整包长。
// 合成 BOSS 的商店采用无卡包规则：4031(-1) 结束访问。
RichonlineLandingResult resolve_richonline_empty_boss_landing(std::uint16_t game_server_id,
    const RichonlineLandingContext& context);
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
