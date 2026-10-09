#include "original_god_rewards.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool ok, const char* reason) { if (!ok) throw std::runtime_error(reason); }
template<class F> void rejects(F action, std::string_view reason) {
    try { action(); } catch (const CodecError& error) {
        if (error.what() != reason) throw std::runtime_error(std::string("expected ")+std::string(reason)+", got "+error.what()); return;
    }
    throw std::runtime_error("expected rejection missing");
}
void wire() {
    const auto choice = parse_original_wealth_choice(Bytes{34,0,0x78,0x56,1,0xcd});
    check(choice.context == 0x5678 && choice.action == 1 && choice.opaque == 0xcd,"34 ctoraction/context/opaque");
    check(encode_original_wealth_result(0x1234,3000,true) == Bytes{0x22,0x40,0x34,0x12,0xb8,0x0b,1},"4022 includes real bankruptcy flag");
    check(encode_original_blessing_result(0x1234,{1044,1038}) == Bytes{0x23,0x40,0x34,0x12,0x14,4,0x0e,4},"4023 two real IDs");
    check(encode_original_misfortune_result(0x1234,{7,7,-1,-1}) == Bytes{0x24,0x40,0x34,0x12,7,7,255,255},"4024 four signed slots");
    check(encode_original_npc_spawn(0x1234,119,3) == Bytes{0x1c,0x40,0x34,0x12,119,0,3,255,255},"401C normal NPC uses proved constructor auxiliary bytes");
    rejects([] { parse_original_wealth_choice(Bytes{34,0,1,0,1}); },"original_wealth_request_length_invalid");
    rejects([] { parse_original_wealth_choice(Bytes{35,0,1,0,1,0}); },"original_wealth_opcode_invalid");
    rejects([] { parse_original_wealth_choice(Bytes{34,0,1,0,0,0}); },"original_wealth_action_invalid");
    rejects([] { encode_original_wealth_result(1,-1,false); },"original_wealth_amount_invalid");
    rejects([] { encode_original_blessing_result(1,{1044,-1}); },"original_blessing_card_invalid");
    rejects([] { encode_original_misfortune_result(1,{-1,2,-1,-1}); },"original_misfortune_slot_invalid");
    rejects([] { encode_original_misfortune_result(1,{8,-1,-1,-1}); },"original_misfortune_slot_invalid");
    rejects([] { encode_original_npc_spawn(1,119,12); },"original_npc_spawn_fields_invalid");
}
void blessing_sequential_synthesis() {
    auto inventory = make_original_inventory();
    for (auto& slot : inventory) slot = {1044,1,{0x71,0x82}};
    inventory[7].id = -1; inventory[7].count = 0;
    OriginalCombination recipe{{},500,true,{}};
    recipe.sources[0] = OriginalCombinationSource{1044,8};
    const OriginalCardCombinations recipes{{},{recipe}};
    const auto result = grant_original_blessing(inventory,0x1234,{1044,1038},recipes,std::array<std::int16_t,1>{500});
    check(result.slots == std::array<std::optional<std::uint8_t>,2>{7,1} && result.combinations.size() == 1 &&
        result.inventory[0] == OriginalCardSlot{500,1,{0x71,0x82}} && result.inventory[1] == OriginalCardSlot{1038,1,{0x71,0x82}},
        "first grant synthesizes before second grant so freed slot is available");
    inventory[7] = {1047,1,{0x71,0x82}};
    const auto full = grant_original_blessing(inventory,0x1234,{1044,1038},recipes,std::array<std::int16_t,1>{500});
    check(full.inventory == inventory && !full.slots[0] && !full.slots[1] && full.message == result.message,
        "full bag still sends both selected IDs without fake card or missing continuation");
    inventory[7] = {-1,0,{0x91,0xa2}};
    const auto limited = grant_original_blessing(inventory,1,{1038,1047},{},{});
    check(limited.slots[0] == 7 && !limited.slots[1] && limited.inventory[7] == OriginalCardSlot{1038,1,{0x91,0xa2}},
        "one free slot keeps first grant and loses second with stable opaque bytes");
}
void misfortune_stack_units_and_empty() {
    auto inventory = make_original_inventory(); inventory[2] = {1044,3,{0x15,0xd1}};
    const auto result = apply_original_misfortune(inventory,1,{2,2,-1,-1});
    check(result.inventory[2] == OriginalCardSlot{1044,1,{0x15,0xd1}},"repeated selected slot removes two stack units, not entire stack");
    const auto final = apply_original_misfortune(result.inventory,1,{2,-1,-1,-1});
    check(final.inventory[2] == OriginalCardSlot{-1,0,{0x15,0xd1}},"final unit preserves slot tails");
    check(apply_original_misfortune(inventory,1,{-1,-1,-1,-1}).inventory == inventory,"empty candidate list has four minus-one sentinels");
    rejects([&] { apply_original_misfortune(result.inventory,1,{2,2,-1,-1}); },"original_misfortune_empty_slot");
    check(result.inventory[2].count == 1,"invalid removal cannot partially commit the input inventory");
}
}
int main() {
    try { wire(); blessing_sequential_synthesis(); misfortune_stack_units_and_empty();
        std::cout << "PASS god wire and ordered blessing/misfortune inventory semantics.\n"; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
