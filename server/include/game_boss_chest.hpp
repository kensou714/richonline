#pragma once
#include "richonline_boss_stage.hpp"
#include "richonline_inventory_date.hpp"

namespace richnet {
struct GameBossChestClaim {
    std::string settlement_operation,stage_key;
    RichonlineBossDrop drop;
    std::array<std::int8_t,10> skill_caps;
    // 服务端兼容策略：无日期键只隐藏不支持的日期，真实到期时间仍必须持久保存。
    bool allow_server_only_expiry=false;
};
struct GameBossChestReceipt {
    bool replayed=false,discarded=false,pending_date=false;
    std::uint32_t owned_key=0;
    std::int64_t expires_at=0;
};
struct GameBossChestNotice { std::int64_t cursor;std::uint32_t owned_key; };
}
