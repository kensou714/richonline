#include "original_movement.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void rejects(F action, std::string_view code) {
    try { action(); } catch (const CodecError& error) { check(error.what() == code,"wrong movement rejection"); return; }
    throw std::runtime_error("missing movement rejection");
}
std::shared_ptr<OriginalMapResources> line() {
    auto map = std::make_shared<OriginalMapResources>();
    map->emp.width = 8; map->emp.height = 1;
    for (std::int16_t tile = 0; tile < 8; ++tile) {
        map->roads.push_back({tile,-1,0});
        if (tile > 0) map->edges.push_back({tile,static_cast<std::int16_t>(tile-1),1});
        if (tile < 7) map->edges.push_back({tile,static_cast<std::int16_t>(tile+1),3});
    }
    return map;
}
OriginalMovement make(std::shared_ptr<const OriginalMapResources> map = line(), std::int16_t tile = 0, std::uint8_t dir = 3) {
    return {std::move(map),{0x3456,7,tile,dir,1,{{0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5},{0xcd},{0xef}}},
        [](std::uint32_t) { return 0U; }};
}
void roll_and_landing() {
    auto move = make();
    const auto packet = move.roll_faces(std::array<std::uint8_t,1>{3},37).messages.at(0);
    check(packet.size() == 28 && packet[7] == 3 && packet[8] == 3 && packet[11] == 0xbf && packet[20] == 0xa5 &&
        read_le(View(packet).subspan(24,4)) == 37,"full dice route, explicit opaque bytes and gold charge");
    rejects([&] { move.handle(OriginalMoveReport{OriginalMoveKind::normal,7,2}); },"original_movement_endpoint_mismatch");
    rejects([&] { move.handle(OriginalMoveReport{OriginalMoveKind::special,7,3}); },"original_movement_unexpected_bomb_report");
    check(move.state().tile == 0 && move.state().phase == OriginalMovePhase::moving,"bad report leaves position pending");
    move.handle(OriginalDiceChoice{7,3,0xcc});
    check(move.state().route.size() == 3 && move.state().dice_count == 3,"preference update preserves moving route");
    const auto result = move.handle(OriginalMoveReport{OriginalMoveKind::normal,7,3});
    check(result.messages == std::vector<Bytes>{{0x13,0x40,0x56,0x34,3,0,0xcd}} && result.event->travelled_steps == 3,
        "landing acknowledges exact endpoint");
    check(move.state().phase == OriginalMovePhase::landing,"landing event must be explicitly completed");
    rejects([&] { move.handle(OriginalRollRequest{7,0}); },"original_movement_roll_while_pending");
    rejects([&] { move.begin_turn(8); },"original_movement_turn_while_pending");
    rejects([&] { move.handle(OriginalMoveReport{OriginalMoveKind::normal,7,3}); },"original_movement_report_without_route");
    move.finish_landing(); move.begin_turn(8);
    rejects([&] { move.handle(OriginalRollRequest{7,0}); },"original_movement_context_mismatch");
    const auto next = move.handle(OriginalRollRequest{8,0}).messages.at(0);
    check(next[6] == 3 && next[8] == 1 && next[9] == 1 && next[10] == 1,"new preference applies next roll");
}
void bomb_stop_and_transfer() {
    auto move = make();
    OriginalMovementEffects effects{{{{2,30},{3,11}},false,{},{}},{0,true,OriginalAttachedBomb{2,4},{}},false};
    move.set_effects(effects); move.roll_faces(std::array<std::uint8_t,1>{4},0);
    rejects([&] { move.handle(OriginalMoveReport{OriginalMoveKind::normal,7,3}); },"original_movement_expected_bomb_report");
    rejects([&] { move.handle(OriginalMoveReport{OriginalMoveKind::special,7,1}); },"original_movement_unexpected_bomb_report");
    const auto stop = move.handle(OriginalMoveReport{OriginalMoveKind::special,7,2});
    check(stop.messages.empty() && stop.event->kind == OriginalStopKind::timed_bomb && stop.event->travelled_steps == 2 &&
        stop.event->consumed_objects == std::vector<std::int16_t>{2},"bomb18 stops without generic landing reply and removes30");
    check(!move.effects().bombs.attached && move.effects().route.objects.contains(3),"unvisited stopper survives interruption");
    rejects([&] { move.finish_landing(); },"original_movement_finish_without_landing");
    move.finish_interruption();
    move.relocate(0,3);
    effects.route.objects.clear(); effects.bombs.others = {{1,1,true,-1,-1,{}}};
    move.set_effects(effects); move.roll_faces(std::array<std::uint8_t,1>{4},0);
    rejects([&] { move.handle(OriginalMoveReport{OriginalMoveKind::special,7,2}); },"original_movement_unexpected_bomb_report");
    const auto landed = move.handle(OriginalMoveReport{OriginalMoveKind::normal,7,4});
    check(!landed.event->bombs.explosion_step && !landed.event->bombs.after.attached &&
        landed.event->bombs.after.others[0].bomb == OriginalAttachedBomb{1,4},"transfer avoids initial-count false explosion");
}
void objects_and_portal() {
    auto move = make();
    move.set_effects({{{{1,30},{3,11},{2,12}},false,{},{}},{},false});
    move.roll_faces(std::array<std::uint8_t,1>{2},0);
    const auto landed = move.handle(OriginalMoveReport{OriginalMoveKind::normal,7,3});
    check(landed.event->consumed_objects == std::vector<std::int16_t>{1,3} && move.effects().route.objects.at(2) == 12,
        "extension and stopper consumed, mine left for landing");
    auto map = line(); map->roads[1].type = 61; map->roads[5].type = 61;
    auto portal = make(map);
    portal.set_effects({{{},true,{{1,5}},{}},{0,true,OriginalAttachedBomb{2,2},{}},false});
    portal.roll_faces(std::array<std::uint8_t,1>{2},0);
    const auto stop = portal.handle(OriginalMoveReport{OriginalMoveKind::special,7,6});
    check(stop.event->travelled_steps == 2 && stop.event->cell.tile == 6,"portal relocation spends no bomb step");
}
void fork_and_cancel() {
    constexpr std::u8string_view file = RICHONLINE_LEGACY_RESOURCE_ROOT;
    const auto root = std::filesystem::path(std::u8string(file.begin(),file.end()));
    const auto map = std::make_shared<OriginalMapResources>(original_map_resources(load_original_emp(root/"Map"/"BS_1_1.emp"),10));
    auto move = make(map,179,1);
    move.set_effects({{{},false,{},{}},{},true});
    move.roll_faces(std::array<std::uint8_t,1>{1},0);
    move.handle(OriginalMoveReport{OriginalMoveKind::normal,7,178});
    check(move.wait_for_direction(),"real fork waits");
    rejects([&] { move.handle(OriginalDirectionChoice{7,3,0xcc}); },"original_movement_direction_unavailable");
    const auto choice = move.handle(OriginalDirectionChoice{7,2,0xcc});
    check(choice.messages == std::vector<Bytes>{{0x35,0x40,0x56,0x34,2,0xef}},"4035 preserves selected heading");
    check(!move.wait_for_direction(),"resolved fork cannot reopen");
    move.finish_landing(); move.begin_turn(8);
    move.roll_faces(std::array<std::uint8_t,1>{1},0);
    check(move.state().route == OriginalRouteTrace{{162,2}},"next roll follows selected branch");
    auto cancel = make(map,179,1); cancel.set_effects({{{},false,{},{}},{},true});
    cancel.roll_faces(std::array<std::uint8_t,1>{1},0); cancel.handle(OriginalMoveReport{OriginalMoveKind::normal,7,178});
    cancel.wait_for_direction(); cancel.handle(OriginalDirectionChoice{7,-1,0xa5});
    check(cancel.state().direction == 1 && !cancel.state().next_direction,"cancel keeps existing heading");
    cancel.finish_landing(); cancel.roll_faces(std::array<std::uint8_t,1>{1},0);
    check(std::none_of(map->edges.begin(),map->edges.end(),[](const auto& edge) { return edge.from == 178 && edge.direction == 1; }),
        "actual T-junction has no continuing left edge");
    check(cancel.state().route == OriginalRouteTrace{{194,0}},"cancelled T-junction chooses available nonreverse branch");
}
void rejected_inputs() {
    auto move = make();
    rejects([&] { move.handle(OriginalRollRequest{7,1}); },"original_movement_roll_parameter_unrecovered");
    rejects([&] { move.roll_faces(std::array<std::uint8_t,1>{7},0); },"original_movement_faces_invalid");
    rejects([&] { move.roll_faces(std::array<std::uint8_t,1>{1},0x80000000); },"original_movement_gold_charge_invalid");
    check(move.state().phase == OriginalMovePhase::ready && move.state().tile == 0,"encoding rejection does not issue route");
    rejects([&] { move.handle(OriginalDiceChoice{7,0,0}); },"original_movement_dice_count_invalid");
    rejects([&] { move.handle(OriginalDirectionChoice{7,2,0}); },"original_movement_direction_not_pending");
    rejects([&] { move.wait_for_direction(); },"original_movement_direction_before_landing");
    move.roll_faces(std::array<std::uint8_t,1>{1},0);
    rejects([&] { move.set_effects({{{},false,{},{}},{},false}); },"original_movement_effects_while_pending");
    rejects([&] { move.relocate(2,3); },"original_movement_relocate_while_pending");
}
}
int main() {
    try {
        roll_and_landing(); bomb_stop_and_transfer(); objects_and_portal(); fork_and_cancel(); rejected_inputs();
        std::cout << "PASS original movement state, bomb transfers, explicit completion, actual-map forks and replay checks.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
