#include "richonline_chance.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value, std::string_view reason) {
    if (!value) throw std::runtime_error(std::string(reason));
}
template<class F> void rejects(F action, std::string_view code) {
    try { action(); } catch (const CodecError& error) { check(error.what() == code,error.what()); return; }
    throw std::runtime_error("expected_rejection");
}
void real_resource_and_wire(const std::filesystem::path& root) {
    // Given the independently verified new-client map-local event and card.
    const auto resources = RichonlineChanceResources::load(root);
    const auto award = resources.single_card("BS_1_1.emp",17,1038);
    // When encoding a nonzero opaque pair, preserve it without inventing semantics.
    const auto packet = encode_richonline_chance_single_card(0xabcd,award,{0xa5,0x5a});
    // Then the exact category-five layout and resource identity agree.
    check(award.event_id() == 17 && award.card_id() == 1038,"new_resource_tuple");
    check(packet == Bytes{0x96,0x40,0xcd,0xab,0x11,0,0xa5,0x5a,0x0e,0x04,0,0},"wire_and_opaque");
    rejects([&] { resources.single_card("BS_1_1.emp",15,1038); },"richonline_chance_category_unsupported");
    rejects([&] { resources.single_card("BS_1_1.emp",17,1044); },"richonline_chance_card_not_candidate");
    rejects([&] { resources.single_card("BS_1_1.emp",18,1038); },"richonline_chance_card_not_candidate");
    rejects([&] { resources.single_card("missing.emp",17,1038); },"richonline_chance_map_missing");
    for (const auto event : {-1,50,32768})
        rejects([&] { resources.single_card("BS_1_1.emp",event,1038); },"richonline_chance_event_invalid");
    for (const auto card : {-1,0,32768,65536})
        rejects([&] { resources.single_card("BS_1_1.emp",17,card); },"richonline_chance_card_invalid");
}
void inventory_and_combination_boundary(const std::filesystem::path& root) {
    const auto resources = RichonlineChanceResources::load(root);
    const auto award = resources.single_card("BS_1_1.emp",17,1038);
    RichonlineChanceInventory inventory{};
    const auto inserted = resources.insert(award,inventory);
    check(inserted[0] == RichonlineChanceCardSlot{1038,1} && inventory[0].card_id == -1,"first_empty_slot");
    inventory[0] = {1039,1}; inventory[2] = {1039,1};
    const auto sparse = resources.insert(award,inventory);
    check(sparse[1] == RichonlineChanceCardSlot{1038,1} && sparse[2] == inventory[2],"first_hole_only");
    inventory.fill({1039,1}); const auto full = inventory;
    rejects([&] { resources.insert(award,inventory); },"richonline_chance_inventory_full");
    check(inventory == full,"full_failure_changed_state");
    inventory.fill({1038,1}); inventory[7] = {}; const auto before_eighth = inventory;
    const auto eighth = resources.insert(award,inventory);
    check(eighth[7] == RichonlineChanceCardSlot{1038,1} && inventory == before_eighth,
        "map_excludes_combination_destination_504");
    rejects([&] { resources.insert(award,eighth); },"richonline_chance_inventory_full");
    inventory = {}; inventory[0] = {1038,-2}; const auto malformed = inventory;
    rejects([&] { resources.insert(award,inventory); },"richonline_chance_inventory_invalid");
    check(inventory == malformed,"invalid_failure_changed_state");
}
void map_scope_and_resource_validation() {
    const std::string news = "a.emp\t0\t0\t0\t0\t0\t0\t,\timg\ttext\n"
        "b.emp\t5\t0\t0\t0\t0\t0\t7\timg\ttext\n"
        "a.emp\t5\t0\t0\t0\t0\t0\t8\timg\ttext\n";
    const std::string props = "[PROP]\nindx=7\ntype=CARD\nenable=true\nhb=true\n"
        "[PROP]\nindx=8\ntype=FUNC\nenable=true\nhb=true\n";
    const auto resources = RichonlineChanceResources::parse(news,props,"");
    check(resources.single_card("b.emp",0,7).event_id() == 0,"index_must_be_map_scoped");
    rejects([&] { resources.single_card("a.emp",1,8); },"richonline_chance_card_invalid");
    rejects([&] { RichonlineChanceResources::parse("a.emp\t5\n",props,""); },"richonline_chance_news_invalid");
    rejects([&] { RichonlineChanceResources::parse(news,props+"[PROP]\nindx=7\ntype=CARD\n",""); },
        "richonline_chance_prop_duplicate");
    rejects([&] { RichonlineChanceResources::parse(news,props,"[ITEM]\nenable=true\nsrc0=7,0\n"); },
        "richonline_chance_combination_invalid");
    const auto disabled = RichonlineChanceResources::parse(news,"[PROP]\nindx=7\ntype=CARD\nenable=false\nhb=true\n","");
    rejects([&] { disabled.single_card("b.emp",0,7); },"richonline_chance_card_invalid");
    const auto combo = RichonlineChanceResources::parse(news,props,
        "[ITEM]\nenable=true\nsrc0=7,2\ndest=8\n");
    RichonlineChanceInventory inventory{}; inventory[0] = {7,1};
    rejects([&] { combo.insert(combo.single_card("b.emp",0,7),inventory); },"richonline_chance_combination_membership_missing");
}
void combination_destination_follows_award_map() {
    const std::string news = "a.emp\t5\t0\t0\t0\t0\t0\t7\timg\ttext\n"
        "b.emp\t5\t0\t0\t0\t0\t0\t7\timg\ttext\n";
    const std::string props = "[PROP]\nindx=7\ntype=CARD\nenable=true\n[PROP]\nindx=8\ntype=CARD\nenable=true\n";
    const auto resources = RichonlineChanceResources::parse(news,props,
        "[ITEM]\nenable=true\nsrc0=7,2\ndest=8\n",{{"a.emp",{7}},{"b.emp",{7,8}}});
    const auto award_a = resources.single_card("a.emp",0,7);
    const auto award_b = resources.single_card("b.emp",0,7);
    check(award_a.map() == "a.emp" && award_b.map() == "b.emp","award_map_identity");
    RichonlineChanceInventory inventory{}; inventory[0] = {7,1}; const auto before = inventory;
    check(resources.insert(award_a,inventory)[1] == RichonlineChanceCardSlot{7,1},"excluded_destination_must_not_combine");
    const auto combined=resources.insert(award_b,inventory);
    check(combined[0]==RichonlineChanceCardSlot{8,1} && combined[1]==RichonlineChanceCardSlot{},"map_combination_wrong");
    check(inventory == before,"map_combination_failure_changed_state");
    const auto changed_resources = RichonlineChanceResources::parse(news,
        "[PROP]\nindx=7\ntype=CARD\nenable=false\n","");
    rejects([&] { changed_resources.insert(award_a,inventory); },"richonline_chance_card_invalid");
}
void stacked_slot_and_ordered_combinations() {
    const auto resources=RichonlineChanceResources::parse("a.emp\t5\t0\t0\t0\t0\t0\t7\timg\ttext\n",
        "[PROP]\nindx=7\ntype=CARD\nenable=true\n[PROP]\nindx=8\ntype=CARD\nenable=true\n[PROP]\nindx=9\ntype=CARD\nenable=true\n",
        "[ITEM]\nenable=true\nsrc0=7,2\ndest=8\n[ITEM]\nenable=true\nsrc0=8,2\ndest=9\n",{{"a.emp",{7,8,9}}});
    RichonlineChanceInventory inventory{}; inventory[3]={7,10}; inventory[6]={8,1};
    const auto after=resources.add("a.emp",7,2,inventory);
    check(after[0]==RichonlineChanceCardSlot{9,1} && after[3]==RichonlineChanceCardSlot{} &&
        after[6]==RichonlineChanceCardSlot{},"ordered_combination_must_count_slots_not_stack");
    const auto first=resources.add("a.emp",7,10,{});
    check(first[0]==RichonlineChanceCardSlot{7,10},"one_stack_is_not_ten_recipe_slots");
    check(resources.discard(first,0)==RichonlineChanceInventory{},"discard_did_not_remove_whole_stack");
    inventory.fill({7,2});
    check(resources.add("a.emp",7,1,inventory)==inventory,"full_add_must_not_combine_or_mutate");
    rejects([&] {resources.add("a.emp",7,0,{});},"richonline_chance_card_invalid");
}
}
int main(int argc, char** argv) {
    try {
        if (argc != 2) throw std::runtime_error("usage: richonline_chance_tests <Richonline-resource-root>");
        real_resource_and_wire(argv[1]); inventory_and_combination_boundary(argv[1]); map_scope_and_resource_validation();
        combination_destination_follows_award_map();
        stacked_slot_and_ordered_combinations();
        std::cout << "PASS new-client chance resources, opaque encoder and bounded inventory\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
