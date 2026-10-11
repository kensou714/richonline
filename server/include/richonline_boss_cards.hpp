#pragma once

// BOSS只保留旧单卡新闻的兼容入口；手牌和商店共用按真人角色绑定的实现。
#include "richonline_player_cards.hpp"

namespace richnet {
struct RichonlineBossCardPolicy {
    std::string map_name;
    std::int32_t event_id,card_id;
    std::array<std::uint8_t,2> opaque6_7;
};
class RichonlineBossCards final : public RichonlinePlayerCards {
public:
    RichonlineBossCards(std::shared_ptr<const RichonlineChanceResources> resources,
        std::uint16_t game_id,const RichonlineBossCardPolicy& policy);
    RichonlineChanceInventory prepare_reward() const;
    std::optional<PreparedLanding> prepare_landing(const RichonlineLandingContext&,
        std::optional<std::int16_t> selected_card={}) const override;
private:
    RichonlineChanceSingleCard award_;
    std::array<std::uint8_t,2> opaque6_7_;
};
}
