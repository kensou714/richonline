#include "original_board.hpp"

#include <functional>
#include <iostream>
#include <limits>

namespace {
using namespace richnet;
void check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}
void rejects(const std::function<void()>& action, std::string_view code) {
    try { action(); } catch (const CodecError& error) {
        check(error.what() == code, std::string("unexpected rejection: ") + error.what());
        return;
    }
    throw std::runtime_error("expected rejection missing");
}
OriginalBoardInit init_fixture() {
    return {0x3456, 1.5, {2024, 2, 29, 4}, 0,
            {{0x1234, 0x2345, 3, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0xe5}}, 0xa7, {0xde, 0xad}};
}
OriginalBoardSnapshot snapshot_fixture() {
    return {0x3456, 0x9abcdef0, 3, {{0x12345678, 0x23456789, 0x3456789a}}, {0xba, 0xad}};
}
void exact_wire_and_roundtrip() {
    const auto init = encode_original_board_init(init_fixture());
    const Bytes expected_init{0x00, 0x40, 0x56, 0x34, 0, 0, 0, 0, 0, 0, 0xf8, 0x3f,
        0xe8, 0x07, 2, 29, 4, 1, 0, 0xa7, 0x34, 0x12, 0x45, 0x23, 3,
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0xe5, 0xde, 0xad};
    check(init == expected_init, "init fields, nonzero opaque bytes, and suffix must match exact wire offsets");
    const auto snapshot = encode_original_board_snapshot(snapshot_fixture());
    const Bytes expected_snapshot{0x04, 0x40, 0x56, 0x34, 0xf0, 0xde, 0xbc, 0x9a,
        3, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, 0x89, 0x67, 0x45, 0x23,
        0x9a, 0x78, 0x56, 0x34, 0xba, 0xad};
    check(snapshot == expected_snapshot, "snapshot context is distinct from gmsv and preserves all funds and suffix");
    const OriginalBoardEnvelope policy{-123, -7, {0x12, 0x34, 0x56, 0x78}};
    for (const auto& plain : {init, snapshot}) {
        const Bytes filler(plain.size() + 2, 0xb5);
        const auto frame = original_board_frame(plain, policy, filler);
        check(frame.wire_type == 299, "board payload must use envelope type 299");
        const auto packet = encode_frame(frame, {Channel::game_s2c, std::nullopt, ClientVersion::legacy});
        const auto decoded = decode_envelope(decode_frame(packet, {Channel::game_s2c, std::nullopt, ClientVersion::legacy}));
        check(decoded.inner_type == -123 && decoded.mode == -7 && decoded.tail == policy.tail,
              "explicit nonzero envelope metadata must survive outer wire encoding");
        check(decode_inner(decoded.encoded) == plain, "board plaintext must survive full wire roundtrip");
    }
}
void calendar_bounds() {
    for (const OriginalCalendar date : {OriginalCalendar{2004, 2, 29, 1}, {2034, 12, 31, 7}, {2025, 2, 28, 3}}) {
        auto init = init_fixture();
        init.calendar = date;
        encode_original_board_init(init);
    }
    for (const OriginalCalendar date : {OriginalCalendar{2003, 12, 31, 1}, {2035, 1, 1, 1}, {2024, 0, 1, 1}, {2024, 13, 1, 1}}) {
        auto init = init_fixture();
        init.calendar = date;
        rejects([&] { encode_original_board_init(init); }, "original_board_calendar_resource_range");
    }
    for (const OriginalCalendar date : {OriginalCalendar{2025, 2, 29, 1}, {2024, 2, 30, 1}, {2024, 4, 31, 1},
                                       {2024, 1, 0, 1}, {2024, 1, 32, 1}, {2024, 1, 1, 0}, {2024, 1, 1, 8}}) {
        auto init = init_fixture();
        init.calendar = date;
        rejects([&] { encode_original_board_init(init); }, "original_board_calendar_day_invalid");
    }
}
void player_and_size_bounds() {
    auto init = init_fixture();
    const auto player = init.players.front();
    init.players.assign(8, player);
    init.players.back().lobby_user_id = -1;
    init.players.back().initial_tile = 0;
    init.players.back().direction = 0;
    init.local_slot = 7;
    init.opaque_suffix.assign(509 - 20 - 8 * 16, 0xe1);
    const auto largest = encode_original_board_init(init);
    check(largest.size() == 509 && largest[132] == 0xff && largest[133] == 0xff,
          "eight-player init must support AI user -1 and 509-byte maximum");
    const auto encoded = original_board_frame(largest, {1, 2, {3, 4, 5, 6}}, Bytes(511, 0x23));
    check(decode_inner(decode_envelope(encoded).encoded) == largest, "maximum-sized payload roundtrip");
    init.opaque_suffix.push_back(1);
    rejects([&] { encode_original_board_init(init); }, "original_board_plain_too_large");
    rejects([&] { original_board_frame(Bytes(510), {1, 2, {3, 4, 5, 6}}, Bytes(512)); }, "original_board_plain_too_large");
    for (const std::size_t count : {std::size_t{0}, std::size_t{9}}) {
        init = init_fixture();
        init.players.assign(count, player);
        rejects([&] { encode_original_board_init(init); }, "original_board_player_count_invalid");
        auto snapshot = snapshot_fixture();
        snapshot.per_player.assign(count, snapshot.per_player.front());
        rejects([&] { encode_original_board_snapshot(snapshot); }, "original_board_player_count_invalid");
    }
    init = init_fixture();
    init.local_slot = 1;
    rejects([&] { encode_original_board_init(init); }, "original_board_local_slot_invalid");
    init = init_fixture();
    init.players.front().direction = 4;
    rejects([&] { encode_original_board_init(init); }, "original_board_direction_invalid");
    init = init_fixture();
    init.players.front().initial_tile = -1;
    rejects([&] { encode_original_board_init(init); }, "original_board_initial_tile_invalid");
    for (const double value : {std::numeric_limits<double>::infinity(), -std::numeric_limits<double>::infinity(),
                               std::numeric_limits<double>::quiet_NaN()}) {
        init = init_fixture();
        init.game_value = value;
        rejects([&] { encode_original_board_init(init); }, "original_board_game_value_invalid");
    }
}
void snapshot_and_startup_bounds() {
    auto snapshot = snapshot_fixture();
    snapshot.per_player.assign(8, {0xffffffff, 0xffffffff, 0xffffffff});
    snapshot.opaque_suffix.assign(509 - 12 - 8 * 12, 0x95);
    check(encode_original_board_snapshot(snapshot).size() == 509, "snapshot preserves full unsigned funds and maximum size");
    snapshot.opaque_suffix.push_back(1);
    rejects([&] { encode_original_board_snapshot(snapshot); }, "original_board_plain_too_large");
    snapshot = snapshot_fixture();
    snapshot.scale = 0;
    rejects([&] { encode_original_board_snapshot(snapshot); }, "original_board_scale_invalid");
    OriginalStartup startup{init_fixture(), snapshot_fixture(), {-2, -3, {4, 5, 6, 7}}};
    validate_original_startup(startup);
    startup.snapshot.gmsv_id = 5;
    rejects([&] { validate_original_startup(startup); }, "original_board_startup_instance_mismatch");
    startup.snapshot = snapshot_fixture();
    startup.snapshot.per_player.push_back({1, 2, 3});
    rejects([&] { validate_original_startup(startup); }, "original_board_startup_count_mismatch");
}
}

int main() {
    try {
        exact_wire_and_roundtrip();
        calendar_bounds();
        player_and_size_bounds();
        snapshot_and_startup_bounds();
        std::cout << "PASS original board initialization, snapshot, opaque bytes, calendar and envelope roundtrip.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
