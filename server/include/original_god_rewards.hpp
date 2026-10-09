#pragma once
#include "original_god_wire.hpp"
#include "original_inventory.hpp"

namespace richnet {
struct OriginalBlessingReward {
    OriginalInventory inventory;
    std::array<std::optional<std::uint8_t>,2> slots;
    std::vector<OriginalAppliedCombination> combinations;
    Bytes message;
};
OriginalBlessingReward grant_original_blessing(const OriginalInventory& inventory,
    std::uint16_t instance, std::array<std::int16_t,2> cards,
    const OriginalCardCombinations& recipes, std::span<const std::int16_t> allowed_outputs);
struct OriginalMisfortuneResult { OriginalInventory inventory; Bytes message; };
OriginalMisfortuneResult apply_original_misfortune(const OriginalInventory& inventory,
    std::uint16_t instance, std::array<std::int8_t,4> slots);
}
