#pragma once
#include "original_boss_board.hpp"
#include "original_game_startup.hpp"
#include "original_movement.hpp"
#include "original_property.hpp"
#include "original_shop.hpp"

namespace richnet {
struct OriginalBossMatchResources {
    std::shared_ptr<const OriginalCardCombinations> combinations;
    OriginalShopCatalog shop;
    OriginalBuildingPolicy buildings;
    std::array<OriginalResearchChoice,7> research;
};
struct OriginalBossMatchWire {
    OriginalMovementWirePolicy movement;
    Bytes turn_suffix, resume_suffix, initial_cards_suffix;
    std::array<std::uint8_t,3> boss_purchase_opaque;
    std::uint8_t boss_choice_opaque;
};
struct OriginalBossMatchPolicy {
    std::array<std::uint8_t,2> dice_counts;
    OriginalBossMatchWire wire;
    OriginalRouteRandom random;
    std::function<OriginalShopClock::time_point()> clock;
    GameLogSink log = {};
};
enum class OriginalBossMatchPhase { loading, dice, movement, shop, property, direction, closed };
class OriginalBossMatch final {
public:
    OriginalBossMatch(OriginalBossBoard board, OriginalBossMatchResources resources, OriginalBossMatchPolicy policy);
    const OriginalStartup& startup() const noexcept { return startup_; }
    OriginalBossMatchPhase phase() const noexcept { return phase_; }
    std::uint32_t context() const noexcept { return context_; }
    std::uint8_t current_slot() const noexcept { return current_; }
    const OriginalPropertyActor& actor(std::uint8_t slot) const { return actors_.at(slot); }
    const OriginalMovementState& movement(std::uint8_t slot) const { return movements_.at(slot).state(); }
    const std::vector<OriginalMapProperty>& properties() const noexcept { return properties_.records(); }
    std::optional<std::uint16_t> closed_shop_context() const;
    bool expired_shop_action(View plain) const;
    std::vector<Bytes> start();
    std::vector<Bytes> action(View plain);
    std::vector<Bytes> poll();
    void close() noexcept;
private:
    OriginalStartup startup_;
    std::shared_ptr<const OriginalMapResources> map_;
    OriginalBossMatchResources resources_;
    OriginalBossMatchPolicy policy_;
    std::array<OriginalPropertyActor,2> actors_;
    std::vector<OriginalMovement> movements_;
    OriginalBossProperties properties_;
    OriginalResearchQueue research_;
    std::optional<OriginalShop> shop_;
    struct ClosedShop { std::uint32_t context; OriginalShopClock::time_point expires; };
    std::optional<ClosedShop> closed_shop_;
    std::uint32_t context_;
    std::uint8_t current_ = 1;
    OriginalBossMatchPhase phase_ = OriginalBossMatchPhase::loading;
    std::uint16_t action_context() const noexcept { return static_cast<std::uint16_t>(context_ & 0xffffU); }
    void begin_turn(std::vector<Bytes>& replies);
    void complete_landing(std::vector<Bytes>& replies);
    void land(const OriginalMovementEvent& event, std::vector<Bytes>& replies);
    void begin_property(std::vector<Bytes>& replies);
    void property_result(const OriginalPropertyRequest& decision, std::vector<Bytes>& replies);
    void continue_property(std::vector<Bytes>& replies);
    void shop_result(OriginalShopResult result, std::vector<Bytes>& replies);
    void grant_card(std::int16_t card, std::vector<Bytes>& replies);
};
OriginalGamePlan original_boss_match_plan(std::shared_ptr<OriginalBossMatch> match);
}
