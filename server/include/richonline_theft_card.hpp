#pragma once

#include "richonline_player_cards.hpp"
#include "lua_server.hpp"

namespace richnet {
struct RichonlineTheftRequest {
    std::uint16_t calendar;
    std::uint8_t inventory_slot,target,target_slot;
};
RichonlineTheftRequest decode_richonline_theft_request(View);

// 抢夺先扣施放卡，再判目标的自动防盗；成功只转移所选卡叠中的一张。
// 准备阶段不改共享库存，提交同时核对双方身份与快照，不允许只扣一方。
class RichonlineTheftPlan final {
public:
    const Bytes& response() const noexcept { return response_; }
    bool protected_by_card() const noexcept { return protection_slot_>=0; }
    std::int16_t transferred_card() const noexcept { return transferred_card_; }
private:
    const RichonlinePlayerCards* attacker_=nullptr;
    const RichonlinePlayerCards* victim_=nullptr;
    RichonlineChanceInventory attacker_before_{},victim_before_{},attacker_after_{},victim_after_{};
    Bytes response_;
    std::int8_t protection_slot_=-1;
    std::int16_t transferred_card_=-1;
    friend RichonlineTheftPlan prepare_richonline_theft(const RichonlineTheftRequest&,
        const RichonlinePlayerCards&,const RichonlinePlayerCards&,const RichonlineChanceResources&,
        bool,const std::shared_ptr<LuaServer>&);
    friend bool commit_richonline_theft(RichonlinePlayerCards&,RichonlinePlayerCards&,const RichonlineTheftPlan&) noexcept;
};
// 第二套库存没有可用1074必须有准入证明；不能把未知装备库存当成空库存。
// 目标手牌已有1074或当前地图禁用1074时，不读取第二套库存。
RichonlineTheftPlan prepare_richonline_theft(const RichonlineTheftRequest&,
    const RichonlinePlayerCards& attacker,const RichonlinePlayerCards& victim,
    const RichonlineChanceResources&,bool secondary_protection_absent,
    const std::shared_ptr<LuaServer>& script={});
bool commit_richonline_theft(RichonlinePlayerCards& attacker,RichonlinePlayerCards& victim,
    const RichonlineTheftPlan&) noexcept;
}
