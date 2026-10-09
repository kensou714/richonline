#include "richonline_movement_wire.hpp"

#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
using D = RichonlineMoveDirection;
void check(bool value, std::string_view code) {
    if (!value) throw std::runtime_error(std::string(code));
}
template<class F> void rejects(F action, std::string_view code) {
    try { action(); } catch (const CodecError& error) { check(error.what() == code, error.what()); return; }
    throw std::runtime_error("expected_rejection");
}
void requests_preserve_distinct_types_and_fields() {
    const auto request = parse_richonline_movement_request(Bytes{0x10,0,0x34,0x12,0x78,0x56,0x34,0xf2});
    const auto& move = std::get<RichonlineMoveRequest10>(request);
    check(move.calendar_counter == 0x1234 && move.parameter == 0xf2345678U, "request10_full_parameter");
    const auto stop = parse_richonline_movement_request(Bytes{0x11,0,0x45,0x23,0xfe,0xff});
    check(std::get<RichonlineMoveStop11>(stop).endpoint == -2 &&
          std::get<RichonlineMoveStop11>(stop).calendar_counter == 0x2345, "stop11_fields");
    const auto countdown = parse_richonline_movement_request(Bytes{0x12,0,0x56,0x34,0x23,0x01});
    check(std::get<RichonlineMoveCountdown12>(countdown).endpoint == 0x123 &&
          std::get<RichonlineMoveCountdown12>(countdown).calendar_counter == 0x3456, "countdown12_fields");
    const auto choice=parse_richonline_movement_request(Bytes{0x14,0,0x78,0x56,3,0xcc});
    check(std::get<RichonlineDiceChoice14>(choice).calendar_counter==0x5678 &&
        std::get<RichonlineDiceChoice14>(choice).count==3 && std::get<RichonlineDiceChoice14>(choice).opaque5==0xcc,
        "dice_choice14_fields");
    const auto pause = parse_richonline_movement_request(Bytes{0x28,0,0x67,0x45,0x34,0x02});
    check(std::get<RichonlineMovePause28>(pause).endpoint == 0x234 &&
          std::get<RichonlineMovePause28>(pause).calendar_counter == 0x4567, "pause28_fields");
    const auto tile = parse_richonline_movement_request(Bytes{0x2a,0,0x78,0x56,0x45,0x03});
    check(std::get<RichonlineMoveSpecialTile2A>(tile).endpoint == 0x345 &&
          std::get<RichonlineMoveSpecialTile2A>(tile).calendar_counter == 0x5678, "tile2a_fields");
}
void request_boundaries_are_rejected() {
    for (const auto opcode : std::array<std::uint8_t,6>{0x10,0x11,0x12,0x14,0x28,0x2a}) {
        const std::size_t length = opcode == 0x10 ? 8U : 6U;
        for (const std::size_t size : {length-1, length+1}) {
            Bytes packet(size, 0); packet[0] = opcode;
            rejects([&] { parse_richonline_movement_request(packet); }, "richonline_movement_length_invalid");
        }
    }
    rejects([] { parse_richonline_movement_request({}); }, "richonline_movement_length_invalid");
    rejects([] { parse_richonline_movement_request(Bytes{0x13,0}); }, "richonline_movement_opcode_unsupported");
    rejects([] { parse_richonline_movement_request(Bytes{0x11,0x40,0,0,0,0}); },
            "richonline_movement_opcode_unsupported");
}
void dice_choice_wire_boundaries() {
    for(const auto count:std::array<std::uint8_t,4>{0,4,127,255}) {
        rejects([&]{parse_richonline_movement_request(Bytes{0x14,0,0x78,0x56,count,0xcc});},
            "richonline_movement_dice_count_invalid");
    }
}
RichonlineRoute4011 route() {
    return {0x2345,0x0167,2,{2,3,-7},{D::right,D::up,D::left,D::down,D::up},5};
}
RichonlineRouteWirePolicy policy() { return {{0xa1,0xb2,0xc3,0xd4},-0x1234567,{0xe5,0xf6}}; }
void turn_matches_fixed_wire_oracle() {
    const auto packet = encode_richonline_turn4010({0x1234,2,5,0xa6},0xb7);
    check(packet == Bytes({0x10,0x40,0x34,0x12,2,5,0xa6,0xb7}), "turn4010_fixed_oracle");
}
void empty_turn_resume_matches_sentinel_oracle() {
    check(encode_richonline_empty_turn420f(0x5678) == Bytes({0x0f,0x42,0x78,0x56,0xff,0xff}),
          "empty_turn420f_sentinel_oracle");
}
void route_matches_fixed_wire_oracle() {
    const auto packet = encode_richonline_route4011(route(),policy());
    check(packet == Bytes({0x11,0x40,0x45,0x23,0x67,1,2,5,2,3,0xf9,
        0x1b,2,0,0,0,0,0,0,0,0xa1,0xb2,0xc3,0xd4,0x99,0xba,0xdc,0xfe,0xe5,0xf6}),
        "route4011_fixed_oracle");
    auto empty_tail = policy(); empty_tail.optional_tail.clear();
    check(encode_richonline_route4011(route(),empty_tail).size() == 28, "explicit_empty_tail_policy");
    auto max_tail = policy(); max_tail.optional_tail.assign(260,0xab);
    max_tail.local_reserve_charge = 0x12345678;
    const auto longest = encode_richonline_route4011(route(),max_tail);
    check(longest.size() == 288 && longest[24] == 0x78 && longest[25] == 0x56 &&
          longest[26] == 0x34 && longest[27] == 0x12 && longest.back() == 0xab, "bounded_tail_and_positive_delta");
}
void maximum_route_and_declared_extension_are_supported() {
    auto value = route(); value.dice_count = 3; value.ui_dice = {12,12,12};
    value.directions.assign(36,D::right); value.required_route_steps = 36;
    const auto packet = encode_richonline_route4011(value,{{1,2,3,4},0,{}});
    check(packet == Bytes({0x11,0x40,0x45,0x23,0x67,1,3,36,12,12,12,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,1,2,3,4,0,0,0,0}), "36_direction_oracle");
    value = route(); value.directions.push_back(D::left); value.required_route_steps = 6;
    check(encode_richonline_route4011(value,policy())[7] == 6, "caller_declared_extension_coverage");
    value.dice_count = 1; value.ui_dice = {1,-128,127}; value.required_route_steps = 1;
    value.directions = {D::up};
    check(encode_richonline_route4011(value,policy())[9] == 0x80, "inactive_ui_bytes_preserved");
}
void unsafe_routes_are_rejected() {
    auto value = route();
    for (const auto count : std::array<std::uint8_t,3>{0,4,255}) {
        value.dice_count = count;
        rejects([&] { encode_richonline_route4011(value,policy()); }, "richonline_movement_dice_count_invalid");
    }
    value = route(); value.directions.assign(37,D::down);
    rejects([&] { encode_richonline_route4011(value,policy()); }, "richonline_movement_direction_count_invalid");
    value = route(); value.directions.clear();
    rejects([&] { encode_richonline_route4011(value,policy()); }, "richonline_movement_direction_count_invalid");
    value = route(); value.directions[0] = static_cast<D>(4);
    rejects([&] { encode_richonline_route4011(value,policy()); }, "richonline_movement_direction_invalid");
    for (const std::array<std::int8_t,3> dice : {std::array<std::int8_t,3>{-1,3,0},{0,0,0},{127,127,0}}) {
        value = route(); value.ui_dice = dice;
        rejects([&] { encode_richonline_route4011(value,policy()); }, "richonline_movement_dice_budget_invalid");
    }
    for (const std::size_t required : {0U,4U,6U,37U}) {
        value = route(); value.required_route_steps = required;
        rejects([&] { encode_richonline_route4011(value,policy()); }, "richonline_movement_route_coverage_invalid");
    }
    value = route(); value.start_position = -1;
    rejects([&] { encode_richonline_route4011(value,policy()); }, "richonline_movement_start_position_invalid");
    auto wire = policy(); wire.optional_tail.assign(261,0);
    rejects([&] { encode_richonline_route4011(route(),wire); }, "richonline_movement_tail_too_large");
    for (const auto slot : std::array<std::int8_t,2>{-1,8})
        rejects([&] { encode_richonline_turn4010({1,slot,0,0},0); }, "richonline_movement_actor_slot_invalid");
    for (const auto anchor : std::array<std::int8_t,2>{-1,8})
        rejects([&] { encode_richonline_turn4010({1,0,anchor,0},0); }, "richonline_movement_round_anchor_invalid");
}
}
int main() {
    try {
        requests_preserve_distinct_types_and_fields(); request_boundaries_are_rejected();
        dice_choice_wire_boundaries();
        turn_matches_fixed_wire_oracle(); route_matches_fixed_wire_oracle();
        empty_turn_resume_matches_sentinel_oracle();
        maximum_route_and_declared_extension_are_supported(); unsafe_routes_are_rejected();
        std::cout << "richonline_movement_wire_tests: PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "richonline_movement_wire_tests: " << error.what() << '\n';
        return 1;
    }
}
