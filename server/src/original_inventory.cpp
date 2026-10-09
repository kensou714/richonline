#include "original_inventory.hpp"
#include <algorithm>

namespace richnet {
void validate_original_card_slot(const OriginalCardSlot& slot) {
    if (slot.id < -1 || (slot.id == -1 ? slot.count != 0 : slot.count <= 0))
        throw CodecError("original_inventory_slot_invalid");
}
void validate_original_inventory(const OriginalInventory& inventory) {
    for (const auto& slot : inventory) validate_original_card_slot(slot);
}
OriginalInventory make_original_inventory() {
    OriginalInventory inventory;
    inventory.fill({-1,0,{0,255}});
    return inventory;
}
OriginalInventoryResult add_original_card(const OriginalInventory& inventory, std::int16_t id, std::int16_t count) {
    validate_original_inventory(inventory);
    if (id < 0 || count <= 0) throw CodecError("original_inventory_add_invalid");
    OriginalInventoryResult result{inventory,std::nullopt};
    for (std::uint8_t index = 0; index < inventory.size(); ++index) {
        if (inventory[index].id != -1) continue;
        result.inventory[index].id = id;
        result.inventory[index].count = count;
        result.slot = index;
        break;
    }
    return result;
}
OriginalInventoryResult remove_original_card(const OriginalInventory& inventory, std::uint8_t slot, std::int16_t count) {
    validate_original_inventory(inventory);
    if (slot >= inventory.size() || count <= 0) throw CodecError("original_inventory_remove_invalid");
    OriginalInventoryResult result{inventory,std::nullopt};
    auto& card = result.inventory[slot];
    if (card.id == -1) return result;
    const auto remaining = static_cast<int>(card.count) - count;
    card.count = static_cast<std::int16_t>(remaining > 0 ? remaining : 0);
    if (card.count == 0) card.id = -1;
    result.slot = slot;
    return result;
}
OriginalInventoryResult discard_original_card(const OriginalInventory& inventory, std::uint8_t slot) {
    validate_original_inventory(inventory);
    if (slot >= inventory.size()) throw CodecError("original_inventory_discard_invalid");
    OriginalInventoryResult result{inventory,std::nullopt};
    auto& card = result.inventory[slot];
    if (card.id == -1) return result;
    card.id = -1;
    card.count = 0;
    result.slot = slot;
    return result;
}
OriginalCombinationResult combine_original_cards(const OriginalInventory& inventory,
    const OriginalCardCombinations& combinations, std::span<const std::int16_t> allowed_outputs) {
    validate_original_inventory(inventory);
    for (const auto& recipe : combinations.items) {
        if (!recipe.enabled || recipe.destination < 0) throw CodecError("original_inventory_recipe_invalid");
        if (!recipe.sources.front()) throw CodecError("original_inventory_recipe_source_invalid");
        for (const auto& source : recipe.sources) {
            if (!source) break;
            if (source->card < 0 || source->count <= 0 || source->count > 32767)
                throw CodecError("original_inventory_recipe_source_invalid");
        }
    }
    OriginalCombinationResult result{inventory,{}};
    for (std::size_t recipe_index = 0; recipe_index < combinations.items.size(); ++recipe_index) {
        const auto& recipe = combinations.items[recipe_index];
        if (!*recipe.enabled || std::find(allowed_outputs.begin(),allowed_outputs.end(),recipe.destination) == allowed_outputs.end()) continue;
        std::uint8_t mask = 0;
        bool matched = true;
        for (const auto& source : recipe.sources) {
            if (!source) break;
            auto remaining = source->count;
            for (std::uint8_t slot = 0; slot < result.inventory.size() && remaining > 0; ++slot) {
                if (result.inventory[slot].id != source->card) continue;
                mask = static_cast<std::uint8_t>(mask | (1U << slot));
                --remaining;
            }
            if (remaining > 0) { matched = false; break; }
        }
        if (!matched) continue;
        std::uint8_t output_slot = 0;
        for (std::uint8_t index = 8; index > 0; --index) {
            const auto slot = static_cast<std::uint8_t>(index - 1);
            if ((mask & (1U << slot)) == 0) continue;
            result.inventory[slot].id = -1;
            result.inventory[slot].count = 0;
            output_slot = slot;
        }
        result.inventory[output_slot].id = recipe.destination;
        result.inventory[output_slot].count = 1;
        result.applied.push_back({recipe_index,output_slot,mask});
    }
    return result;
}
}
