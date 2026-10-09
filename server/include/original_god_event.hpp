#pragma once
#include "original_god_state.hpp"
#include "original_god_rewards.hpp"
#include "original_wealth.hpp"

namespace richnet {
struct OriginalGodEventSetup {
    std::uint16_t instance, context;
    std::uint8_t actor;
    OriginalGodTransition transition;
};
class OriginalGodEvent final {
public:
    explicit OriginalGodEvent(OriginalGodEventSetup setup);
    const OriginalGodTransition& transition() const noexcept { return setup_.transition; }
    bool awaiting_bankruptcy() const noexcept { return wealth_.awaiting_bankruptcy(); }
    OriginalBlessingReward bless(const OriginalInventory& inventory, std::array<std::int16_t,2> cards,
        const OriginalCardCombinations& recipes, std::span<const std::int16_t> allowed_outputs);
    OriginalMisfortuneResult discard(const OriginalInventory& inventory, std::array<std::int8_t,4> slots);
    OriginalWealthOutcome settle(const OriginalWealthChoice& request, const OriginalWealthSnapshot& snapshot, std::int32_t amount);
    void finish_bankruptcy(std::uint16_t context);
    OriginalGodOrigin finish() const;
private:
    OriginalGodEventSetup setup_;
    OriginalWealthSettlement wealth_;
};
}
