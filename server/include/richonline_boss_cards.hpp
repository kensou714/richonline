#pragma once

// 新版 BOSS 卡片桥接：奖励和使用先准备结果，再显式提交库存变更。

#include "richonline_boss_turns.hpp"
#include "richonline_chance.hpp"
#include "richonline_controlled_dice.hpp"
#include "richonline_card_wire.hpp"

#include <memory>
#include <string>

namespace richnet {
class RichonlineShopCatalog;
struct RichonlineBossCardPolicy {
    std::string map_name;
    std::int32_t event_id, card_id;
    std::array<std::uint8_t,2> opaque6_7;
};
// Static rewards whose 4029 continuation is implemented by this BOSS owner.
bool richonline_boss_card_reward_tile(std::int8_t static_type) noexcept;
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
    struct PreparedShuffle {
        RichonlineChanceInventory source_inventory, remaining_inventory;
        Bytes confirmation40e8;
    };
    struct PreparedReward {
        std::int16_t card;
        RichonlineChanceInventory inventory;
    };
    RichonlineBossCards(std::shared_ptr<const RichonlineChanceResources> resources,
        std::uint16_t game_id, const RichonlineBossCardPolicy& policy);
    void configure_tile_rewards(std::vector<std::int16_t> playable_cards,RichonlineRouteChooser random);
    void configure_tile_rewards(std::vector<std::int16_t> playable_cards,RichonlineRouteChooser random,
        const RichonlineShopCatalog& resale);
    const std::vector<std::int16_t>& tile_reward_cards() const noexcept { return tile_reward_cards_; }
    const RichonlineChanceInventory& inventory() const noexcept { return inventory_; }
    std::string_view map_name() const noexcept { return award_.map(); }
    RichonlineChanceInventory prepare_reward() const;
    RichonlineChanceInventory prepare_add(std::int16_t card_id,std::int16_t count=1) const;
    PreparedReward prepare_random_reward() const;
    PreparedReward prepare_random_reward(const RichonlineChanceInventory& source) const;
    PreparedDiscard prepare_discard(const RichonlineCardDiscardRequest50& request,std::int8_t actor) const;
    std::optional<PendingTargetEffect> prepare_target_effect(const RichonlineTargetCardRequest& request) const;
    std::optional<PreparedConsumption> prepare_consumption(std::int8_t slot,std::int16_t card_id) const;
    // Current session has one human hand and an empty synthetic BOSS hand.
    PreparedShuffle prepare_shuffle(std::int8_t slot,std::uint8_t actor,const RichonlineRouteChooser& random) const;
    // 顺序使用扣卡后原槽号，必须覆盖全部非空卡叠；按协议顺序重放资源插入与合成。
    PreparedShuffle prepare_shuffle_order(std::int8_t slot,std::uint8_t actor,
        const std::vector<std::uint8_t>& order) const;
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
