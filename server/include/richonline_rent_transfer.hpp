#pragma once

#include "richonline_chance.hpp"
#include "richonline_game_ledger.hpp"
#include <memory>

namespace richnet {
class LuaServer;
struct RichonlineRentTransferChoice {
    std::uint16_t calendar;
    std::int8_t target;
    std::uint8_t unassigned_padding;
};
RichonlineRentTransferChoice decode_richonline_rent_transfer_choice(View);
enum class RichonlineRentTransferKind { rent, trade };
// 6712B0的type0租金/type1贸易中心共用资金与续行；不混用type2饭店或type3入狱。
struct RichonlineRentTransferState {
    std::uint16_t game_id,calendar;
    std::uint8_t original_payer,recipient;
    std::uint32_t amount;
    std::vector<RichonlineGameFundsSnapshot> funds;
    std::vector<bool> eligible;
    RichonlineChanceInventory inventory;
    std::int8_t card_slot;
    RichonlineRentTransferKind kind=RichonlineRentTransferKind::rent;
};
struct RichonlineRentTransferPlan {
    std::int8_t target;
    std::uint8_t payer;
    std::uint32_t charged;
    bool consume_card,bankrupt;
    // 收款在前、付款在后；同一人时第二个before已经包含本次存款收入。
    std::vector<RichonlineGameFundsUpdate> funds;
    RichonlineChanceInventory inventory;
    Bytes response;
};
// 只准备，绝不写余额/库存。调用方须复核待决上下文，再将全部步骤原子提交。
// 超时取消是显式服务端恢复策略，不冒充客户端托管的随机-1/-2选择。
RichonlineRentTransferPlan plan_richonline_rent_transfer(const RichonlineRentTransferState&,
    const RichonlineRentTransferChoice&,bool timed_out,std::shared_ptr<LuaServer> script={});
}
