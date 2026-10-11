#pragma once

#include "richonline_classic_property.hpp"
#include "lua_server.hpp"

namespace richnet {
// 96购地/97换地/98换屋/100查封/101拆屋/102怪兽/119涨价；仅97/98/101带目标地产WORD。
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
// 购地同时提交现金、库存、产权；查封/涨价提交街区，交换/拆除提交一至两块地产。
bool commit_richonline_classic_property_card(RichonlinePlayerCards&,RichonlineClassicProperty&,
    RichonlineGameLedger&,std::span<const std::uint8_t> active,const RichonlineClassicPropertyCardPlan&);
}
