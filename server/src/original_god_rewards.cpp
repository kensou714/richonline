#include "original_god_rewards.hpp"

namespace richnet {
OriginalBlessingReward grant_original_blessing(const OriginalInventory& inventory,
    std::uint16_t instance, std::array<std::int16_t,2> cards,
    const OriginalCardCombinations& recipes, std::span<const std::int16_t> allowed_outputs) {
    validate_original_inventory(inventory);
    OriginalBlessingReward result{inventory,{},{},encode_original_blessing_result(instance,cards)};
    for (std::size_t index = 0; index < cards.size(); ++index) {
        const auto added = add_original_card(result.inventory,cards[index],1);
        result.slots[index] = added.slot;
        if (!added.slot) continue;
        auto combined = combine_original_cards(added.inventory,recipes,allowed_outputs);
        result.inventory = std::move(combined.inventory);
        result.combinations.insert(result.combinations.end(),combined.applied.begin(),combined.applied.end());
    }
    return result;
}
OriginalMisfortuneResult apply_original_misfortune(const OriginalInventory& inventory,
    std::uint16_t instance, std::array<std::int8_t,4> slots) {
    validate_original_inventory(inventory);
    OriginalMisfortuneResult result{inventory,encode_original_misfortune_result(instance,slots)};
    for (const auto slot : slots) {
        if (slot == -1) continue;
        const auto index = static_cast<std::uint8_t>(slot);
        if (result.inventory[index].id == -1) throw CodecError("original_misfortune_empty_slot");
        result.inventory = remove_original_card(result.inventory,index,1).inventory;
    }
    return result;
}
}
