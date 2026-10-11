#pragma once

#include "richonline_game_ledger.hpp"
#include <memory>

namespace richnet {
class LuaServer;
// 仅准备所有活动角色的月初存款利息；调用者负责日期去重及整笔提交。
// 客户端由4010自行排本地6041，因此这里没有网络消息或确认等待。
std::vector<RichonlineGameFundsUpdate> prepare_richonline_classic_interest(
    std::span<const std::uint8_t> active,const RichonlineGameLedger& ledger,
    const std::shared_ptr<LuaServer>& script);
}
