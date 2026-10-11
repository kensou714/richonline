#pragma once
#include "richonline_boss_turns.hpp"
#include "richonline_game_ledger.hpp"

namespace richnet {
struct RichonlineClassicMoneyNews {
    std::uint16_t opcode;
    std::uint32_t amount;
    // 只有UI30分支有图索引；UI4分支没有这个字段，不能补一个占位WORD。
    std::optional<std::int16_t> picture;
};
struct RichonlineClassicNewsPlan {
    RichonlineGameFundsUpdate funds;
    std::uint32_t fines_before,fines_after;
    bool bankrupt;
    std::vector<Bytes> messages;
};
// 对应406D/406E收入及已核实的单人罚款消息。只准备，不选概率、不写账本。
// available_pictures须来自当前客户端UI30资源；累计罚款初值由准入层明确提供。
RichonlineClassicNewsPlan prepare_richonline_classic_money_news(std::uint16_t game,
    const RichonlineLandingContext&,const RichonlineClassicMoneyNews&,
    const RichonlineGameFundsSnapshot&,std::uint32_t fines,
    std::span<const std::int16_t> available_pictures,const std::shared_ptr<LuaServer>& script);
}
