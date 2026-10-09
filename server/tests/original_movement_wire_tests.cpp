#include "original_movement_wire.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}
template<class Action> void rejects(Action action, std::string_view code) {
    try { action(); }
    catch (const CodecError& error) {
        check(error.what() == code, std::string("expected ") + std::string(code) + ", got " + error.what());
        return;
    }
    throw std::runtime_error("expected rejection: " + std::string(code));
}
OriginalRollRoute route_fixture() {
    return {0x3456, 0x1234, 2, {6,3,0}, {3,2,1,0,1},
        {0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xca,0xfe,0xba,0xbe}, 300};
}
void typed_requests() {
    const auto roll = std::get<OriginalRollRequest>(parse_original_movement_request(Bytes{16,0,0xef,0xcd,0x78,0x56,0x34,0x12}));
    check(roll.context == 0xcdef && roll.parameter == 0x12345678, "roll context and opaque parameter preserved independently of downstream ID");
    for (const auto opcode : {17U,18U}) {
        const auto report = std::get<OriginalMoveReport>(parse_original_movement_request(Bytes{static_cast<std::uint8_t>(opcode),0,0xef,0xcd,0xff,0x7f}));
        check(report.context == 0xcdef && report.tile == 32767 && report.kind == (opcode == 17 ? OriginalMoveKind::normal : OriginalMoveKind::special),
              "normal and special move reports remain distinct at signed tile maximum");
    }
    for (const std::uint8_t count : {std::uint8_t{1},std::uint8_t{2},std::uint8_t{3}}) {
        const auto choice = std::get<OriginalDiceChoice>(parse_original_movement_request(Bytes{20,0,0xef,0xcd,count,0xcc}));
        check(choice.context == 0xcdef && choice.count == count && choice.opaque == 0xcc, "dice count and unwritten opaque byte preserved");
    }
    for (const std::uint8_t direction : {std::uint8_t{0xff},std::uint8_t{0},std::uint8_t{1},std::uint8_t{2},std::uint8_t{3}}) {
        const auto choice = std::get<OriginalDirectionChoice>(parse_original_movement_request(Bytes{52,0,0xef,0xcd,direction,0xa5}));
        check(choice.context == 0xcdef && choice.direction == (direction == 255 ? -1 : direction) && choice.opaque == 0xa5,
              "direction includes signed cancellation without interpreting opaque tail");
    }
}
void request_rejections() {
    for (const auto opcode : {16U,17U,18U,20U,52U}) {
        Bytes valid{static_cast<std::uint8_t>(opcode),0,1,0,1,0xcc};
        if (opcode == 16) valid.resize(8);
        for (std::size_t size = 0; size < valid.size(); ++size)
            rejects([&] { parse_original_movement_request(View(valid).first(size)); }, "original_movement_request_length_invalid");
        valid.push_back(0);
        rejects([&] { parse_original_movement_request(valid); }, "original_movement_request_length_invalid");
    }
    rejects([] { parse_original_movement_request(Bytes{22,0,1,0,1,0xcc}); }, "original_movement_opcode_unsupported");
    for (const auto value : {0U,4U,255U})
        rejects([&] { parse_original_movement_request(Bytes{20,0,1,0,static_cast<std::uint8_t>(value),0xcc}); }, "original_movement_dice_count_invalid");
    for (const auto value : {4U,128U,254U})
        rejects([&] { parse_original_movement_request(Bytes{52,0,1,0,static_cast<std::uint8_t>(value),0xcc}); }, "original_movement_direction_invalid");
    for (const auto opcode : {17U,18U})
        rejects([&] { parse_original_movement_request(Bytes{static_cast<std::uint8_t>(opcode),0,1,0,0xff,0xff}); }, "original_movement_tile_invalid");
}
void exact_route_storage() {
    const Bytes expected{0x11,0x40,0x56,0x34,0x34,0x12,2,5,6,3,0,
        0x1b,0xcd,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xca,0xfe,0xba,0xbe,0x2c,1,0,0};
    check(encode_original_roll_route(route_fixture()) == expected, "five steps overwrite active bits only, retaining partial byte and complete tail");
    auto route = route_fixture();
    route.directions.clear();
    for (unsigned i = 0; i < 9; ++i) route.directions.insert(route.directions.end(), {0,1,2,3});
    route.gold_charge = 0x7fffffff;
    const Bytes maximum{0x11,0x40,0x56,0x34,0x34,0x12,2,36,6,3,0,
        0xe4,0xe4,0xe4,0xe4,0xe4,0xe4,0xe4,0xe4,0xe4,0xca,0xfe,0xba,0xbe,0xff,0xff,0xff,0x7f};
    const auto plain = encode_original_roll_route(route);
    check(plain == maximum, "36 route steps fit nine bytes with explicit maximum charge and four preserved tail bytes");
    check(decode_inner(encode_inner(plain, Bytes(plain.size()+2,0x97))) == maximum, "maximum route survives existing codec roundtrip");
    route.directions.clear(); route.dice_count = 0; route.gold_charge = 0;
    rejects([&] { encode_original_roll_route(route); }, "original_movement_dice_count_invalid");
    route.dice_count = 2;
    rejects([&] { encode_original_roll_route(route); }, "original_movement_route_length_invalid");
    route.directions = {3};
    check(read_le(View(encode_original_roll_route(route)).subspan(24,4)) == 0,"ordinary roll has explicit no-charge value");
}
void downlink_validation() {
    auto route = route_fixture(); route.directions.assign(37,0);
    rejects([&] { encode_original_roll_route(route); }, "original_movement_route_length_invalid");
    route = route_fixture(); route.directions[0] = 4;
    rejects([&] { encode_original_roll_route(route); }, "original_movement_direction_invalid");
    route = route_fixture(); route.dice_count = 4;
    rejects([&] { encode_original_roll_route(route); }, "original_movement_dice_count_invalid");
    for (const auto face : {0U,7U,255U}) {
        route = route_fixture(); route.faces[1] = static_cast<std::uint8_t>(face);
        rejects([&] { encode_original_roll_route(route); }, "original_movement_faces_invalid");
    }
    route = route_fixture(); route.start_tile = -1;
    rejects([&] { encode_original_roll_route(route); }, "original_movement_tile_invalid");
    route = route_fixture(); route.gold_charge = 0x80000000;
    rejects([&] { encode_original_roll_route(route); }, "original_movement_gold_charge_invalid");
    check(encode_original_landing({0x3456,0x1234,{0xcc,0xaa}}) == Bytes({0x13,0x40,0x56,0x34,0x34,0x12,0xcc,0xaa}),
          "landing exact signed tile and caller suffix");
    check(encode_original_direction_result({0x3456,-1,{0xcc}}) == Bytes({0x35,0x40,0x56,0x34,0xff,0xcc}),
          "direction cancel result preserves opaque suffix");
    check(encode_original_direction_result({0x3456,3,{}}) == Bytes({0x35,0x40,0x56,0x34,3}), "minimal direction result adds no inferred padding");
    check(encode_original_landing({1,0,Bytes(503,0x96)}).size() == 509 &&
          encode_original_direction_result({1,0,Bytes(504,0x96)}).size() == 509, "explicit suffix within encoder maximum");
    rejects([] { encode_original_landing({1,-1,{}}); }, "original_movement_tile_invalid");
    rejects([] { encode_original_direction_result({1,4,{}}); }, "original_movement_direction_invalid");
    rejects([] { encode_original_direction_result({1,-2,{}}); }, "original_movement_direction_invalid");
    rejects([] { encode_original_landing({1,0,Bytes(504)}); }, "original_movement_plain_too_large");
    rejects([] { encode_original_direction_result({1,0,Bytes(505)}); }, "original_movement_plain_too_large");
}
}
int main() {
    try {
        typed_requests(); request_rejections(); exact_route_storage(); downlink_validation();
        std::cout << "PASS original typed movement requests, exact route bytes, opaque storage, boundaries and landing/direction results\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
