#pragma once
#include "richonline_player_cards.hpp"
#include "lua_server.hpp"

namespace richnet {
// 清除卡1078只准备主手牌和目标状态；收容/行动权限由共享会话核对。
class RichonlineClassicClearStatusPlan final {
public:
    const Bytes& response() const noexcept {return response_;}
    std::uint8_t target() const noexcept {return target_;}
private:
    const RichonlinePlayerCards* cards_=nullptr;
    RichonlineChanceInventory inventory_before_{},inventory_after_{};
    std::vector<RichonlineActorStatus> statuses_before_;
    std::vector<std::uint8_t> active_before_;
    RichonlineActorStatus target_after_;
    std::uint8_t target_=0;
    Bytes response_;
    friend RichonlineClassicClearStatusPlan prepare_richonline_classic_clear_status(View,std::uint16_t,
        const RichonlinePlayerCards&,std::span<const RichonlineActorStatus>,std::span<const std::uint8_t>,
        const std::shared_ptr<LuaServer>&);
    friend bool commit_richonline_classic_clear_status(RichonlinePlayerCards&,
        std::span<RichonlineActorStatus>,std::span<const std::uint8_t>,const RichonlineClassicClearStatusPlan&) noexcept;
};
RichonlineClassicClearStatusPlan prepare_richonline_classic_clear_status(View,std::uint16_t calendar,
    const RichonlinePlayerCards&,std::span<const RichonlineActorStatus>,std::span<const std::uint8_t> active,
    const std::shared_ptr<LuaServer>& script={});
// 共享会话须先核验关系快照，成功后无异常地清除双向同盟；NPC独立时钟仍待接入。
bool commit_richonline_classic_clear_status(RichonlinePlayerCards&,std::span<RichonlineActorStatus>,
    std::span<const std::uint8_t> active,const RichonlineClassicClearStatusPlan&) noexcept;
}
