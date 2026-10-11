#pragma once

#include "richonline_classic_property.hpp"

namespace richnet {
// UI15的0025只有opcode和日历，没有玩家选择的点数。
std::uint16_t decode_richonline_classic_trade_request(View);
struct RichonlineClassicTradeResult {
    std::int8_t result;
    std::int32_t quote;
    Bytes message;
};
// 原服概率未恢复。调用者显式选1..6；-1仅用于取消，不能发0让转盘永远转动。
// 只准备4027与原生报价，不改资金、手牌或产权。
RichonlineClassicTradeResult prepare_richonline_classic_trade(std::uint16_t game_id,
    const RichonlineClassicPropertyState&,std::uint32_t monetary_scale,std::int8_t result,
    std::shared_ptr<LuaServer> script={});
}
