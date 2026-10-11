#pragma once

#include "richonline_player_cards.hpp"
#include "lua_server.hpp"

namespace richnet {
// 40DE让客户端遍历全部活动角色清除五种武器，再扣施放者的一张1115。
// 准备阶段保存每名角色的手牌对象与库存，提交前统一复核，避免只清施放者造成不同步。
class RichonlineClassicWeaponTreatyPlan final {
public:
    const Bytes& response() const noexcept { return response_; }
private:
    std::vector<std::shared_ptr<RichonlinePlayerCards>> owners_;
    std::vector<RichonlineChanceInventory> before_,after_;
    std::vector<std::uint8_t> active_;
    Bytes response_;
    friend RichonlineClassicWeaponTreatyPlan prepare_richonline_classic_weapon_treaty(View,
        std::uint16_t,std::uint8_t,std::span<const std::shared_ptr<RichonlinePlayerCards>>,
        std::span<const std::uint8_t>,const std::shared_ptr<LuaServer>&);
    friend bool commit_richonline_classic_weapon_treaty(
        std::span<const std::shared_ptr<RichonlinePlayerCards>>,std::span<const std::uint8_t>,
        const RichonlineClassicWeaponTreatyPlan&);
};
RichonlineClassicWeaponTreatyPlan prepare_richonline_classic_weapon_treaty(View,
    std::uint16_t calendar,std::uint8_t actor,std::span<const std::shared_ptr<RichonlinePlayerCards>>,
    std::span<const std::uint8_t> active,const std::shared_ptr<LuaServer>& script={});
// 会话串行执行；所有可能拒绝的检查都在写入之前完成，随后只作noexcept固定库存赋值。
bool commit_richonline_classic_weapon_treaty(std::span<const std::shared_ptr<RichonlinePlayerCards>>,
    std::span<const std::uint8_t> active,const RichonlineClassicWeaponTreatyPlan&);
}
