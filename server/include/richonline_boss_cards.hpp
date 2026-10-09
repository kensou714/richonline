#pragma once

// 新版 BOSS 卡片桥接：奖励和使用先准备结果，再显式提交库存变更。

#include "richonline_boss_turns.hpp"
#include "richonline_chance.hpp"
#include "richonline_controlled_dice.hpp"
#include "richonline_card_wire.hpp"

#include <memory>
#include <string>

namespace richnet {
struct RichonlineBossCardPolicy {
    std::string map_name;
    std::int32_t event_id, card_id;
    std::array<std::uint8_t,2> opaque6_7;
};
class RichonlineBossCards final {
public:
    struct PreparedUse {
        Bytes confirmation40b7;
        RichonlineChanceInventory remaining_inventory;
        std::uint8_t die;
    };
    struct PreparedDiscard {
        Bytes confirmation4033;
        RichonlineChanceInventory remaining_inventory;
    };
    struct PendingTargetEffect {
        RichonlineTargetCardRequest request;
        RichonlineChanceInventory source_inventory, remaining_inventory;
    };
    struct PreparedConsumption {
        RichonlineChanceInventory source_inventory, remaining_inventory;
        std::int8_t slot;
        std::int16_t card_id;
    };
    RichonlineBossCards(std::shared_ptr<const RichonlineChanceResources> resources,
        std::uint16_t game_id, const RichonlineBossCardPolicy& policy);
    void configure_tile_rewards(std::vector<std::int16_t> playable_cards,RichonlineRouteChooser random);
    const std::vector<std::int16_t>& tile_reward_cards() const noexcept { return tile_reward_cards_; }
    const RichonlineChanceInventory& inventory() const noexcept { return inventory_; }
    std::string_view map_name() const noexcept { return award_.map(); }
    RichonlineChanceInventory prepare_reward() const;
    RichonlineChanceInventory prepare_add(std::int16_t card_id,std::int16_t count=1) const;
    PreparedDiscard prepare_discard(const RichonlineCardDiscardRequest50& request,std::int8_t actor) const;
    std::optional<PendingTargetEffect> prepare_target_effect(const RichonlineTargetCardRequest& request) const;
    std::optional<PreparedConsumption> prepare_consumption(std::int8_t slot,std::int16_t card_id) const;
    void commit_consumption(const PreparedConsumption& prepared);
    // Resolve map/visibility/status/damage rules before committing and encoding its confirmation.
    void commit_target_effect(const PendingTargetEffect& pending);
    void commit_inventory(const RichonlineChanceInventory& inventory) noexcept;
    std::optional<RichonlineLandingResult> land(const RichonlineLandingContext& context);
    std::optional<PreparedUse> prepare_use(const RichonlineCardDiceRequest103& request) const;
    void commit_use(const PreparedUse& prepared) noexcept;
private:
    std::shared_ptr<const RichonlineChanceResources> resources_;
    RichonlineChanceSingleCard award_;
    std::uint16_t game_id_;
    std::array<std::uint8_t,2> opaque6_7_;
    RichonlineChanceInventory inventory_{};
    std::vector<std::int16_t> tile_reward_cards_;
    RichonlineRouteChooser tile_random_;
};
}
