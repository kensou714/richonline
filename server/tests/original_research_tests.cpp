#include "original_research.hpp"
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
std::array<OriginalResearchChoice,7> choices() {
    return {{{1044,1},{1038,1},{1047,2},{1181,2},{1063,3},{1070,4},{500,5}}};
}
OriginalMapProperty property(std::int16_t id = 5) { return {id,0,11,11,7,100}; }
OriginalResearchInventories inventories() {
    OriginalResearchInventories result;
    for (std::uint8_t player = 0; player < result.size(); ++player) {
        result[player] = make_original_inventory();
        for (std::uint8_t slot = 0; slot < result[player].size(); ++slot) result[player][slot].opaque = {player,static_cast<std::uint8_t>(0xd0 + slot)};
    }
    return result;
}
const OriginalCardCombinations no_recipes{{},{}};
void schedule_owner_visitor_and_capacity() {
    OriginalResearchQueue queue(choices());
    const auto owner = queue.schedule(0,property(),3);
    check(owner == std::vector<std::uint8_t>{0,1,2} && queue.jobs()[0]->days == 2 && queue.jobs()[1]->days == 4 && queue.jobs()[2]->days == 6,
          "owner schedules three delays d/2d/3d in first free slots");
    const auto visitor = queue.schedule(1,property(),2);
    check(visitor == std::vector<std::uint8_t>{3} && queue.jobs()[3]->card == 1038 && queue.jobs()[3]->recipient == 1,
          "visitor gets one job for chosen level");
    for (unsigned i = 4; i < 63; ++i) check(queue.schedule(1,property(),1).size() == 1, "fill queue through slot62");
    check(queue.schedule(0,property(),1) == std::vector<std::uint8_t>{63}, "one remaining slot partially accepts owner batch");
    const auto full = queue.jobs();
    check(queue.schedule(1,property(),1).empty() && queue.jobs() == full, "full queue schedule leaves all jobs unchanged");
    OriginalResearchQueue two_free(choices());
    for (unsigned i = 0; i < 62; ++i) two_free.schedule(1,property(),1);
    check(two_free.schedule(0,property(),1) == std::vector<std::uint8_t>{62,63}, "two free slots accept only first two owner jobs");
}
void advance_recipient_and_property_cancellation() {
    OriginalResearchQueue queue(choices());
    queue.schedule(0,property(),3);
    const auto before = queue.jobs();
    const auto bags = inventories();
    std::array records{property()};
    auto result = queue.advance(1,records,{bags,no_recipes,{}});
    check(queue.jobs() == before && result.completed.empty(), "other player turn does not decrement positive days");
    records[0].owner = 7;
    result = queue.advance(0,records,{bags,no_recipes,{}});
    check(queue.jobs()[0]->days == 1 && result.cancelled.empty(), "ownership transfer does not cancel research");
    result = queue.advance(0,records,{bags,no_recipes,{}});
    check(result.completed.size() == 1 && result.completed[0].job_index == 0 && result.completed[0].card_slot == 0 &&
          result.inventories[0][0] == OriginalCardSlot{1047,1,{0,0xd0}} && !queue.jobs()[0], "recipient second turn grants exactly one card and frees job");
    records[0].level = 2;
    result = queue.advance(7,records,{result.inventories,no_recipes,{}});
    check(result.cancelled == std::vector<std::uint8_t>{1,2} && result.completed.empty(), "insufficient building level cancels remaining jobs on any turn");
    records[0] = property(); queue.schedule(1,records[0],1); records[0].kind = 12;
    result = queue.advance(7,records,{bags,no_recipes,{}});
    check(result.cancelled == std::vector<std::uint8_t>{0}, "changed building kind cancels and first free slot is reused");
}
void zero_negative_days_and_full_inventory() {
    auto values = choices(); values[0].days = 0;
    OriginalResearchQueue zero(values);
    zero.schedule(1,property(),1);
    auto bags = inventories();
    const std::array records{property()};
    auto result = zero.advance(7,records,{bags,no_recipes,{}});
    check(result.completed.size() == 1 && result.inventories[1][0].id == 1044, "zero day expires even on another recipient turn");
    values[0].days = -1;
    OriginalResearchQueue negative(values); negative.schedule(1,property(),1);
    const auto pending = negative.jobs();
    result = negative.advance(1,records,{bags,no_recipes,{}});
    check(negative.jobs() == pending && result.completed.empty(), "negative signed days do not decrement or complete");
    values[0].days = 43;
    OriginalResearchQueue wrapped(values); wrapped.schedule(0,property(),1);
    check(wrapped.jobs()[0]->days == 43 && wrapped.jobs()[1]->days == 86 && wrapped.jobs()[2]->days == -127,
          "owner multiplied days use original signed byte storage");
    OriginalResearchQueue full(choices()); full.schedule(1,property(),1);
    for (auto& slot : bags[1]) { slot.id = 7; slot.count = 1; }
    result = full.advance(1,records,{bags,no_recipes,{}});
    check(result.completed.size() == 1 && !result.completed[0].card_slot && result.inventories == bags && !full.jobs()[0],
          "full inventory loses research output but clears completed job");
}
void completion_combines_and_failure_is_atomic() {
    OriginalResearchQueue queue(choices()); queue.schedule(1,property(),1);
    auto bags = inventories(); bags[1][2] = {1044,7,{1,0xd2}};
    OriginalCombination recipe{{},27,true,{}};
    recipe.sources[0] = OriginalCombinationSource{1044,2};
    const OriginalCardCombinations combinations{{},{recipe}};
    const std::array<std::int16_t,1> outputs{27};
    const std::array records{property()};
    const auto result = queue.advance(1,records,{bags,combinations,outputs});
    check(result.completed.size() == 1 && result.completed[0].combinations.size() == 1 &&
          result.inventories[1][0] == OriginalCardSlot{27,1,{1,0xd0}} && result.inventories[1][2] == OriginalCardSlot{-1,0,{1,0xd2}},
          "research grant executes existing slot-based combination once");
    queue.schedule(1,property(),1); queue.schedule(1,property(6),1);
    const auto before = queue.jobs();
    rejects([&] { queue.advance(1,records,{bags,no_recipes,{}}); }, "original_research_property_missing");
    check(queue.jobs() == before, "late missing property does not partially decrement or commit earlier grants");
    OriginalCardCombinations invalid = combinations; invalid.items[0].enabled.reset();
    const std::array all_records{property(),property(6)};
    rejects([&] { queue.advance(1,all_records,{bags,invalid,outputs}); }, "original_inventory_recipe_invalid");
    check(queue.jobs() == before, "combination failure does not clear pending research");
    auto unavailable = property(); unavailable.kind = 12;
    rejects([&] { queue.schedule(1,unavailable,1); }, "original_research_choice_unavailable");
    rejects([&] { queue.schedule(8,property(),1); }, "original_research_recipient_invalid");
    rejects([&] { queue.schedule(1,property(),0); }, "original_research_choice_unavailable");
    rejects([&] { queue.schedule(1,property(),8); }, "original_research_choice_unavailable");
    check(queue.jobs() == before, "invalid scheduling cannot partially change queue");
}
void simultaneous_grants_follow_queue_slots() {
    OriginalResearchQueue queue(choices());
    queue.schedule(1,property(),1); queue.schedule(1,property(),2);
    const auto bags = inventories();
    const std::array records{property()};
    const auto result = queue.advance(1,records,{bags,no_recipes,{}});
    check(result.completed.size() == 2 && result.completed[0].job_index == 0 && result.completed[1].job_index == 1 &&
          result.inventories[1][0].id == 1044 && result.inventories[1][1].id == 1038,
          "consecutive local6061 emissions keep ascending queue order and card slots");
}
}
int main() {
    try {
        schedule_owner_visitor_and_capacity(); advance_recipient_and_property_cancellation();
        zero_negative_days_and_full_inventory(); completion_combines_and_failure_is_atomic();
        simultaneous_grants_follow_queue_slots();
        std::cout << "PASS original research queue capacity, dates, recipients, cancellation, inventory synthesis and atomic failures\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
