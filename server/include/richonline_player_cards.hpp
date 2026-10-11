#pragma once

// 每名真人独占一份手牌和奖励池；角色槽来自已认证的局内分配，不来自客户端请求。

#include "richonline_boss_turns.hpp"
#include "richonline_chance.hpp"
#include "richonline_controlled_dice.hpp"
#include "richonline_card_wire.hpp"

#include <memory>
#include <string>

namespace richnet {
class RichonlineShopCatalog;
// Static rewards whose 4029 continuation is implemented by this BOSS owner.
bool richonline_boss_card_reward_tile(std::int8_t static_type) noexcept;
class RichonlinePlayerCards {
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
    struct PreparedLanding {
        RichonlineChanceInventory source_inventory,remaining_inventory;
        RichonlineLandingResult result;
    };
    RichonlinePlayerCards(std::shared_ptr<const RichonlineChanceResources> resources,
        std::uint16_t game_id,std::string map,std::uint8_t actor,std::uint8_t mode);
    virtual ~RichonlinePlayerCards() = default;
    // 会话和商店保存该对象的引用；禁止复制/赋值后把既有计划换绑到另一角色。
    RichonlinePlayerCards(const RichonlinePlayerCards&) = delete;
    RichonlinePlayerCards& operator=(const RichonlinePlayerCards&) = delete;
    std::uint8_t actor_slot() const noexcept { return actor_; }
    std::uint8_t game_mode() const noexcept { return mode_; }
    std::uint16_t game_id() const noexcept { return game_id_; }
    void configure_tile_rewards(std::vector<std::int16_t> playable_cards,RichonlineRouteChooser random);
    void configure_tile_rewards(std::vector<std::int16_t> playable_cards,RichonlineRouteChooser random,
        const RichonlineShopCatalog& resale);
    const std::vector<std::int16_t>& tile_reward_cards() const noexcept { return tile_reward_cards_; }
    const RichonlineChanceInventory& inventory() const noexcept { return inventory_; }
    std::string_view map_name() const noexcept { return map_; }
    RichonlineChanceInventory prepare_add(std::int16_t card_id,std::int16_t count=1) const;
    PreparedReward prepare_random_reward() const;
    PreparedReward prepare_random_reward(const RichonlineChanceInventory& source) const;
    PreparedDiscard prepare_discard(const RichonlineCardDiscardRequest50& request,std::int8_t actor) const;
    std::optional<PendingTargetEffect> prepare_target_effect(const RichonlineTargetCardRequest& request) const;
    std::optional<PreparedConsumption> prepare_consumption(std::int8_t slot,std::int16_t card_id) const;
    // 洗牌只修改本角色手牌，顺序包含扣卡后的全部非空叠；不与其他角色合并。
    PreparedShuffle prepare_shuffle(std::int8_t slot,std::uint8_t actor,const RichonlineRouteChooser& random) const;
    // 顺序使用扣卡后原槽号，必须覆盖全部非空卡叠；按协议顺序重放资源插入与合成。
    PreparedShuffle prepare_shuffle_order(std::int8_t slot,std::uint8_t actor,
        const std::vector<std::uint8_t>& order) const;
    void commit_consumption(const PreparedConsumption& prepared);
    // Resolve map/visibility/status/damage rules before committing and encoding its confirmation.
    void commit_target_effect(const PendingTargetEffect& pending);
    void commit_inventory(const RichonlineChanceInventory& inventory) noexcept;
    std::vector<std::int16_t> tile_candidates(std::int8_t type) const;
    virtual std::optional<PreparedLanding> prepare_landing(const RichonlineLandingContext& context,
        std::optional<std::int16_t> selected_card={}) const;
    void commit_landing(const PreparedLanding& prepared);
    std::optional<RichonlineLandingResult> land(const RichonlineLandingContext& context);
    std::optional<PreparedUse> prepare_use(const RichonlineCardDiceRequest103& request) const;
    void commit_use(const PreparedUse& prepared) noexcept;
protected:
    std::shared_ptr<const RichonlineChanceResources> resources_;
    std::uint16_t game_id_;
    RichonlineChanceInventory inventory_{};
private:
    std::string map_;
    std::uint8_t actor_,mode_;
    std::vector<std::int16_t> tile_reward_cards_;
    RichonlineRouteChooser tile_random_;
};
}
