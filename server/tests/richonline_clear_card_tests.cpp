#include "richonline_clear_card.hpp"
#include <functional>
#include <iostream>
#include <stdexcept>

using namespace richnet;
namespace {
void check(bool value) {
    if (!value) throw std::runtime_error("clear_card_expectation_failed");
}
void rejects(const std::function<void()>& action) {
    try { action(); } catch (const CodecError&) { return; }
    throw std::runtime_error("clear_card_expected_rejection");
}
}
int main() {
    const Bytes wire{160, 0, 0x34, 0x12, 3, 0};
    const auto request = decode_richonline_clear_card160(wire);
    check(request.calendar == 0x1234 && request.inventory_slot == 3 && request.inventory_bank == 0);
    const RichonlineClearCardContext context{0x4567, 0x1234, 1, 1, true, true};
    RichonlineChanceInventory inventory{};
    inventory[3] = {502, 2};
    inventory[4] = {507, 1};
    RichonlineGroundSnapshot ground{{{1, {0, 255, 255}}, {2, {9, 255, 255}},
        {3, {11, 1, 255}}, {4, {12, 1, 3}}, {5, {27, 1, 3}}, {6, {30, 255, 255}}}, 42};
    const auto plan = plan_richonline_clear_card(request, context, inventory, ground);
    check(plan.response40f0 == Bytes({0xf0, 0x40, 0x67, 0x45, 3, 0}));
    check(plan.expected_ground == ground && plan.after_ground.empty());
    check(plan.expected_inventory == inventory && plan.after_inventory[3].count == 1);
    check(plan.after_inventory[4] == inventory[4] && ground.objects.size() == 6);
    inventory[3].count = 1;
    const auto last = plan_richonline_clear_card(request, context, inventory, ground);
    check(last.after_inventory[3] == RichonlineChanceCardSlot{});
    const auto empty = plan_richonline_clear_card(request, context, inventory, {{}, 43});
    check(empty.after_ground.empty() && empty.after_inventory[3].count == 0);

    auto wrong = wire; wrong.push_back(0); rejects([&] { decode_richonline_clear_card160(wrong); });
    wrong = wire; wrong[0] = 164; rejects([&] { decode_richonline_clear_card160(wrong); });
    wrong = wire; wrong[4] = 255; rejects([&] { decode_richonline_clear_card160(wrong); });
    wrong[4] = 8; rejects([&] { decode_richonline_clear_card160(wrong); });
    wrong = wire; wrong[5] = 1; rejects([&] { decode_richonline_clear_card160(wrong); });
    auto altered = context; altered.calendar++; rejects([&] { plan_richonline_clear_card(request, altered, inventory, ground); });
    altered = context; altered.active_actor = 0; rejects([&] { plan_richonline_clear_card(request, altered, inventory, ground); });
    altered = context; altered.requesting_actor = -1; rejects([&] { plan_richonline_clear_card(request, altered, inventory, ground); });
    altered = context; altered.roll_phase = false; rejects([&] { plan_richonline_clear_card(request, altered, inventory, ground); });
    altered = context; altered.requesting_actor_can_act = false; rejects([&] { plan_richonline_clear_card(request, altered, inventory, ground); });
    inventory[3] = {507, 1}; rejects([&] { plan_richonline_clear_card(request, context, inventory, ground); });
    inventory[3] = {502, 0}; rejects([&] { plan_richonline_clear_card(request, context, inventory, ground); });
    std::cout << "clear card protocol and shared ground planning passed\n";
}
