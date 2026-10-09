#pragma once
#include "codec.hpp"
#include "original_card_resources.hpp"

namespace richnet {
struct OriginalCardSlot {
    std::int16_t id, count;
    std::array<std::uint8_t,2> opaque;
    bool operator==(const OriginalCardSlot&) const = default;
};
using OriginalInventory = std::array<OriginalCardSlot,8>;
struct OriginalInventoryResult {
    OriginalInventory inventory;
    std::optional<std::uint8_t> slot;
};
struct OriginalAppliedCombination {
    std::size_t recipe_index;
    std::uint8_t output_slot, consumed_mask;
};
struct OriginalCombinationResult {
    OriginalInventory inventory;
    std::vector<OriginalAppliedCombination> applied;
};
void validate_original_card_slot(const OriginalCardSlot& slot);
void validate_original_inventory(const OriginalInventory& inventory);
OriginalInventory make_original_inventory();
OriginalInventoryResult add_original_card(const OriginalInventory& inventory, std::int16_t id, std::int16_t count);
OriginalInventoryResult remove_original_card(const OriginalInventory& inventory, std::uint8_t slot, std::int16_t count);
OriginalInventoryResult discard_original_card(const OriginalInventory& inventory, std::uint8_t slot);
OriginalCombinationResult combine_original_cards(const OriginalInventory& inventory,
    const OriginalCardCombinations& combinations, std::span<const std::int16_t> allowed_outputs);
}
