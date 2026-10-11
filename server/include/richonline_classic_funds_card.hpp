#pragma once

#include "richonline_player_cards.hpp"
#include "richonline_game_ledger.hpp"
#include "lua_server.hpp"

namespace richnet {
// 只描述已核实的主手牌请求；目标卡的末字节没有业务含义。
struct RichonlineClassicFundsCardRequest {
    std::uint16_t opcode,calendar;
    std::uint8_t inventory_slot;
    std::optional<std::uint8_t> target;
};
RichonlineClassicFundsCardRequest decode_richonline_classic_funds_card(View);

class RichonlineClassicFundsCardPlan final {
public:
    const Bytes& response() const noexcept { return response_; }
private:
    const RichonlinePlayerCards* cards_=nullptr;
    const RichonlineGameLedger* ledger_=nullptr;
    RichonlineChanceInventory before_inventory_{},after_inventory_{};
    std::vector<std::uint8_t> active_;
    std::vector<RichonlineGameFundsUpdate> funds_;
    Bytes response_;
    friend RichonlineClassicFundsCardPlan prepare_richonline_classic_funds_card(View,
        std::uint16_t,const RichonlinePlayerCards&,const RichonlineGameLedger&,
        std::span<const std::uint8_t>,const std::shared_ptr<LuaServer>&);
    friend bool commit_richonline_classic_funds_card(RichonlinePlayerCards&,RichonlineGameLedger&,
        std::span<const std::uint8_t>,const RichonlineClassicFundsCardPlan&);
};
// 查税分别转移现金/存款的十分之一；均贫均分双方现金；经典均富均分活动角色存款。
// 只准备，不扣卡、不发包。回合权、收容状态与选人资格由经典会话核对。
RichonlineClassicFundsCardPlan prepare_richonline_classic_funds_card(View,std::uint16_t calendar,
    const RichonlinePlayerCards&,const RichonlineGameLedger&,std::span<const std::uint8_t> active,
    const std::shared_ptr<LuaServer>& script={});
// 账本先检查全部受影响角色的余额/版本，再在同一事务中扣卡；任何拒绝不保留部分更新。
bool commit_richonline_classic_funds_card(RichonlinePlayerCards&,RichonlineGameLedger&,
    std::span<const std::uint8_t> active,const RichonlineClassicFundsCardPlan&);
}
