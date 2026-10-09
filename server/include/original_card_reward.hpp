#pragma once
#include "original_inventory.hpp"

namespace richnet {
struct OriginalCardReward {
    OriginalInventory inventory;
    bool inserted;
    std::vector<OriginalAppliedCombination> combinations;
    Bytes message;
};
struct OriginalCardRewardRequest {
    std::uint16_t instance;
    std::int16_t card;
};
OriginalCardReward grant_original_card(const OriginalInventory& inventory,
    OriginalCardRewardRequest request, const OriginalCardCombinations& recipes,
    std::span<const std::int16_t> allowed_outputs);
}
