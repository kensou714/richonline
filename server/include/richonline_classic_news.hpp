#pragma once
#include "richonline_boss_turns.hpp"
#include "richonline_game_ledger.hpp"

namespace richnet {
// NEW 64F2A0 -> 7D9C70在每次开局将G+C80设为5000，与地图起始现金无关。
inline constexpr std::uint32_t richonline_classic_initial_news_fines=5000;
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
// 图片索引按NEW UI30的718DE0初始化表校验，不能把数组容量当成已加载图片。
RichonlineClassicNewsPlan prepare_richonline_classic_money_news(std::uint16_t game,
    const RichonlineLandingContext&,const RichonlineClassicMoneyNews&,
    const RichonlineGameFundsSnapshot&,std::uint32_t fines,
    const std::shared_ptr<LuaServer>& script);
}
