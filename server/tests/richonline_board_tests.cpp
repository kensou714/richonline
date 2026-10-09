#include "richonline_board.hpp"

#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
void require(bool condition, std::string_view reason) {
    if (!condition) throw std::runtime_error(std::string(reason));
}
template<class Action> void rejects(Action action, std::string_view expected) {
    try { action(); } catch (const CodecError& error) {
        require(error.what() == expected, "wrong_rejection"); return;
    }
    throw std::runtime_error("expected_rejection");
}
RichonlineBoardInit fixture() {
    return {0x1234, {0,0,0,0,0,0,0xf0,0x3f}, 2026, 10, 9, 5, 0, 0xa9,
        {{25, 0x123, 2, {1,2,3,4,5,6,7,8,9,10}, 0xb9},
         {-1, 0x234, 3, {11,12,13,14,15,16,17,18,19,20}, 0xc9}}};
}
void exact_startup_bytes() {
    const Bytes expected{0x00,0x40,0x34,0x12,0,0,0,0,0,0,0xf0,0x3f,0xea,7,10,9,5,2,0,0xa9,
        25,0,0x23,1,2,1,2,3,4,5,6,7,8,9,10,0xb9,
        0xff,0xff,0x34,2,3,11,12,13,14,15,16,17,18,19,20,0xc9};
    require(encode_richonline_board_init(fixture()) == expected, "4000_exact_fields_wrong");
    auto eight = fixture();
    while (eight.participants.size() < 8) eight.participants.push_back(eight.participants.back());
    require(encode_richonline_board_init(eight).size() == 148, "eight_slot_boundary_wrong");
    eight.participants.push_back(eight.participants.back());
    rejects([&] { encode_richonline_board_init(eight); }, "richonline_board_slot_count_invalid");
    auto invalid = fixture(); invalid.local_slot = 1;
    rejects([&] { encode_richonline_board_init(invalid); }, "richonline_board_local_identity_invalid");
    invalid = fixture(); invalid.participants[1].lobby_identity = 25;
    rejects([&] { encode_richonline_board_init(invalid); }, "richonline_board_duplicate_identity");
    invalid = fixture(); invalid.month = 2; invalid.day = 30;
    rejects([&] { encode_richonline_board_init(invalid); }, "richonline_board_calendar_invalid");
}
void snapshot_absolute_slot_and_envelope() {
    const RichonlineBoardSnapshot snapshot{0x1234,0x10203040,100,{{0x11223344,0x55667788,0xaabbccdd},{7,8,9}}};
    const Bytes expected{4,0x40,0x34,0x12,0x40,0x30,0x20,0x10,100,0,0,0,
        0x44,0x33,0x22,0x11,0x88,0x77,0x66,0x55,0xdd,0xcc,0xbb,0xaa,
        7,0,0,0,8,0,0,0,9,0,0,0};
    require(encode_richonline_board_snapshot(snapshot) == expected, "4004_slot_stride_wrong");
    const auto framed = richonline_board_frame(expected, {0x123, -7}, Bytes(expected.size()+2, 0xab));
    require(framed.payload.size() == 5 + 2*(expected.size()+2), "new_envelope_has_legacy_tail");
    const auto envelope = decode_envelope(framed, ClientVersion::richonline);
    require(envelope.inner_type == 0x123 && envelope.mode == -7 && decode_inner(envelope.encoded) == expected,
        "envelope_tag_mode_or_body_changed");
}
}
int main() {
    try { exact_startup_bytes(); snapshot_absolute_slot_and_envelope(); std::cout << "PASS Richonline board field codecs\n"; }
    catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
