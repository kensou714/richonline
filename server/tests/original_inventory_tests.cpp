#include "original_inventory.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool condition, std::string_view reason) {
    if (!condition) throw std::runtime_error(std::string(reason));
}
template<class Action> void rejects(Action action, std::string_view code) {
    try { action(); }
    catch (const CodecError& error) {
        check(error.what() == code, std::string("expected ") + std::string(code) + ", got " + error.what());
        return;
    }
    throw std::runtime_error("expected rejection: " + std::string(code));
}
OriginalInventory tagged_inventory() {
    auto inventory = make_original_inventory();
    for (std::uint8_t i = 0; i < inventory.size(); ++i) inventory[i].opaque = {static_cast<std::uint8_t>(0xa0 + i),static_cast<std::uint8_t>(0xd0 + i)};
    return inventory;
}
void insert_without_merge() {
    const auto initial = make_original_inventory();
    for (const auto& slot : initial) check(slot == OriginalCardSlot{-1,0,{0,255}}, "constructor exact known six-byte record");
    auto inventory = tagged_inventory();
    inventory[0] = {7,3,inventory[0].opaque};
    inventory[2] = {9,1,inventory[2].opaque};
    const auto result = add_original_card(inventory,7,2);
    check(result.slot == 1 && result.inventory[1] == OriginalCardSlot{7,2,{0xa1,0xd1}}, "duplicate ID occupies first empty slot with its old tail");
    check(result.inventory[0] == inventory[0] && result.inventory[2] == inventory[2] && inventory[1].id == -1,
          "insert leaves existing cards and input unchanged");
    for (std::size_t i = 0; i < inventory.size(); ++i) {
        inventory[i].id = 7;
        inventory[i].count = 32767;
    }
    const auto full = add_original_card(inventory,7,1);
    check(!full.slot && full.inventory == inventory, "full inventory does not merge duplicates or mutate on failure");
}
void remove_and_discard_preserve_slot_tails() {
    auto inventory = tagged_inventory();
    inventory[5] = {27,3,inventory[5].opaque};
    const auto reduced = remove_original_card(inventory,5,1);
    check(reduced.slot == 5 && reduced.inventory[5] == OriginalCardSlot{27,2,{0xa5,0xd5}}, "partial count removal retains ID and opaque bytes");
    for (const std::int16_t count : {std::int16_t{3},std::int16_t{4},std::int16_t{32767}}) {
        const auto removed = remove_original_card(inventory,5,count);
        check(removed.slot == 5 && removed.inventory[5] == OriginalCardSlot{-1,0,{0xa5,0xd5}}, "exhausted removal clamps and clears only id/count");
    }
    const auto discarded = discard_original_card(inventory,5);
    check(discarded.slot == 5 && discarded.inventory[5] == OriginalCardSlot{-1,0,{0xa5,0xd5}}, "discard clears whole stack not one item");
    check(inventory[5].count == 3, "pure operations retain input");
    const auto absent_remove = remove_original_card(inventory,7,1);
    const auto absent_discard = discard_original_card(inventory,7);
    check(!absent_remove.slot && absent_remove.inventory == inventory && !absent_discard.slot && absent_discard.inventory == inventory,
          "empty slot actions are stable business failures");
    const auto refilled = add_original_card(discarded.inventory,32767,32767);
    check(refilled.slot == 0 && refilled.inventory[0] == OriginalCardSlot{32767,32767,{0xa0,0xd0}}, "signed maximum valid IDs/counts survive insert");
}
void invalid_parameters() {
    const auto inventory = tagged_inventory();
    for (const OriginalCardSlot slot : {OriginalCardSlot{-2,0,{1,2}}, {-1,1,{1,2}}, {1,0,{1,2}}, {1,-1,{1,2}}}) {
        rejects([&] { validate_original_card_slot(slot); }, "original_inventory_slot_invalid");
        auto invalid = inventory; invalid[6] = slot;
        rejects([&] { add_original_card(invalid,1,1); }, "original_inventory_slot_invalid");
        rejects([&] { remove_original_card(invalid,0,1); }, "original_inventory_slot_invalid");
        rejects([&] { discard_original_card(invalid,0); }, "original_inventory_slot_invalid");
    }
    rejects([&] { add_original_card(inventory,-1,1); }, "original_inventory_add_invalid");
    rejects([&] { add_original_card(inventory,1,0); }, "original_inventory_add_invalid");
    rejects([&] { add_original_card(inventory,1,-1); }, "original_inventory_add_invalid");
    rejects([&] { remove_original_card(inventory,8,1); }, "original_inventory_remove_invalid");
    rejects([&] { remove_original_card(inventory,0,0); }, "original_inventory_remove_invalid");
    rejects([&] { remove_original_card(inventory,0,-1); }, "original_inventory_remove_invalid");
    rejects([&] { discard_original_card(inventory,8); }, "original_inventory_discard_invalid");
}
OriginalCombination recipe(std::int16_t source, std::int32_t slots, std::int16_t destination) {
    OriginalCombination value{{},destination,true,{}};
    value.sources[0] = OriginalCombinationSource{source,slots};
    return value;
}
void combination_uses_slots_and_preserves_tail() {
    auto inventory = tagged_inventory();
    inventory[1] = {7,99,inventory[1].opaque};
    const OriginalCardCombinations combinations{{},{recipe(7,2,27)}};
    const std::array<std::int16_t,1> outputs{27};
    const auto missing = combine_original_cards(inventory,combinations,outputs);
    check(missing.applied.empty() && missing.inventory == inventory, "stack count99 cannot satisfy two required source slots");
    inventory[5] = {7,3,inventory[5].opaque};
    inventory[7] = {7,4,inventory[7].opaque};
    const auto result = combine_original_cards(inventory,combinations,outputs);
    check(result.applied.size() == 1 && result.applied[0].recipe_index == 0 && result.applied[0].output_slot == 1 &&
          result.applied[0].consumed_mask == 0x22, "first two matching slots selected and lowest slot receives output");
    check(result.inventory[1] == OriginalCardSlot{27,1,{0xa1,0xd1}} && result.inventory[5] == OriginalCardSlot{-1,0,{0xa5,0xd5}} &&
          result.inventory[7] == inventory[7], "combine consumes whole selected slots and preserves tails and excess matches");
    check(inventory[1].count == 99, "combine leaves input unchanged");
    const auto blocked = combine_original_cards(inventory,combinations,std::array<std::int16_t,1>{1044});
    check(blocked.applied.empty() && blocked.inventory == inventory, "destination must exist in caller supplied map pair table");
}
void combination_order_reuse_and_gaps() {
    auto inventory = tagged_inventory();
    inventory[3] = {7,2,inventory[3].opaque};
    OriginalCardCombinations combinations{{},{recipe(7,1,27),recipe(27,1,1044),recipe(7,1,27)}};
    const std::array<std::int16_t,2> outputs{27,1044};
    auto result = combine_original_cards(inventory,combinations,outputs);
    check(result.applied.size() == 2 && result.applied[0].recipe_index == 0 && result.applied[1].recipe_index == 1 &&
          result.inventory[3] == OriginalCardSlot{1044,1,{0xa3,0xd3}}, "later recipes consume prior outputs and earlier recipe is never retried");
    combinations.items = {recipe(7,1,27)};
    combinations.items[0].sources[1] = OriginalCombinationSource{7,1};
    result = combine_original_cards(inventory,combinations,outputs);
    check(result.applied.size() == 1 && result.applied[0].consumed_mask == 8 && result.inventory[3].id == 27,
          "duplicate ingredient scans reuse the same slot exactly as original client");
    combinations.items[0].sources[1].reset();
    combinations.items[0].sources[2] = OriginalCombinationSource{999,8};
    result = combine_original_cards(inventory,combinations,outputs);
    check(result.applied.size() == 1 && result.inventory[3].id == 27, "source scan ends at first missing source");
    combinations.items[0].enabled = false;
    result = combine_original_cards(inventory,combinations,outputs);
    check(result.applied.empty() && result.inventory == inventory, "disabled recipes retain input");
    combinations.items[0].enabled.reset();
    rejects([&] { combine_original_cards(inventory,combinations,outputs); }, "original_inventory_recipe_invalid");
    combinations.items[0] = recipe(7,0,27);
    rejects([&] { combine_original_cards(inventory,combinations,outputs); }, "original_inventory_recipe_source_invalid");
}
}
int main() {
    try {
        insert_without_merge(); remove_and_discard_preserve_slot_tails(); invalid_parameters();
        combination_uses_slots_and_preserves_tail(); combination_order_reuse_and_gaps();
        std::cout << "PASS original inventory insertion, removal, discard and ordered combination with opaque preservation\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
