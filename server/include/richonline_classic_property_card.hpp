#pragma once

#include "richonline_classic_property.hpp"
#include "lua_server.hpp"

namespace richnet {
// 经典购地/交换/开店/建屋/拆除/查封/涨价/天使/恶魔/建筑改造卡。
// 97/98/99/101/125..129带目标地产WORD；123带规范后的建筑格WORD。
class RichonlineClassicPropertyCardPlan final {
public:
    const Bytes& response() const noexcept {return response_;}
    std::span<const RichonlineClassicPropertyState> properties_before() const noexcept {return change_->before();}
private:
    const RichonlinePlayerCards* cards_=nullptr;
    const RichonlineGameLedger* ledger_=nullptr;
    const RichonlineClassicProperty* property_=nullptr;
    RichonlineChanceInventory before_inventory_{},after_inventory_{};
    std::vector<std::uint8_t> active_;
    std::optional<RichonlineClassicProperty::CardChange> change_;
    std::optional<RichonlineGameFundsUpdate> funds_;
    Bytes response_;
    friend RichonlineClassicPropertyCardPlan prepare_richonline_classic_property_card(View,
        std::uint16_t,std::int16_t,std::int32_t,const RichonlinePlayerCards&,
        const RichonlineClassicProperty&,const RichonlineGameLedger&,std::span<const std::uint8_t>,
        const std::shared_ptr<LuaServer>&);
    friend bool commit_richonline_classic_property_card(RichonlinePlayerCards&,RichonlineClassicProperty&,
        RichonlineGameLedger&,std::span<const std::uint8_t>,const RichonlineClassicPropertyCardPlan&);
};
// current_property从当前角色权威位置映射，land_equipment是原始P+152；只准备，不产生副作用。
RichonlineClassicPropertyCardPlan prepare_richonline_classic_property_card(View,std::uint16_t calendar,
    std::int16_t current_property,std::int32_t land_equipment,const RichonlinePlayerCards&,
    const RichonlineClassicProperty&,const RichonlineGameLedger&,std::span<const std::uint8_t> active,
    const std::shared_ptr<LuaServer>& script={});
// 购地提交现金、库存、产权；街区卡提交全组，交换/拆除提交一至两块地产。
bool commit_richonline_classic_property_card(RichonlinePlayerCards&,RichonlineClassicProperty&,
    RichonlineGameLedger&,std::span<const std::uint8_t> active,const RichonlineClassicPropertyCardPlan&);
}
