#pragma once

#include "richonline_actor_status.hpp"
#include "richonline_boss_stage.hpp"

namespace richnet {
class LuaServer;
struct RichonlineBossRecoveryPlan {
    std::uint32_t amount=0;
    // 客户端在恢复分支排6060后清资格，即使倍率使增量取整为0也会清除。
    bool consume_eligibility=false;
};
// 只计算原生回血，不提交资金或发送消息。调用方须在光环/破产结算之前按队列顺序
// 提交，并在账本提交成功后清资格；无受伤资格或达到初始HP上限时保留原状态。
RichonlineBossRecoveryPlan plan_richonline_boss_recovery(const RichonlineNativeBossRecovery&,
    std::uint32_t cash_cap,std::uint32_t cash,const RichonlineActorStatus&,LuaServer* script=nullptr);
}
