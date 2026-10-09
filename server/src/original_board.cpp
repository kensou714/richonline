#include "original_board.hpp"

#include <bit>
#include <cmath>

namespace richnet {
namespace {
void validate_count(std::size_t count) {
    if (count < 1 || count > 8) throw CodecError("original_board_player_count_invalid");
}
void validate_size(std::size_t fixed, std::size_t suffix) {
    if (suffix > 509 - fixed) throw CodecError("original_board_plain_too_large");
}
void validate_calendar(const OriginalCalendar& calendar) {
    if (calendar.year < 2004 || calendar.year > 2034 || calendar.month < 1 || calendar.month > 12)
        throw CodecError("original_board_calendar_resource_range");
    constexpr std::array<std::uint8_t, 12> days{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const auto max_day = calendar.month == 2 && (calendar.year - 2004) % 4 == 0
        ? 29 : days[calendar.month - 1];
    if (calendar.day < 1 || calendar.day > max_day || calendar.weekday_index < 1 || calendar.weekday_index > 7)
        throw CodecError("original_board_calendar_day_invalid");
}
}

Bytes encode_original_board_init(const OriginalBoardInit& init) {
    validate_count(init.players.size());
    validate_size(20 + 16 * init.players.size(), init.opaque_suffix.size());
    validate_calendar(init.calendar);
    if (init.local_slot >= init.players.size()) throw CodecError("original_board_local_slot_invalid");
    if (!std::isfinite(init.game_value)) throw CodecError("original_board_game_value_invalid");
    Bytes plain;
    plain.reserve(20 + 16 * init.players.size() + init.opaque_suffix.size());
    append_le(plain, 0x4000, 2);
    append_le(plain, init.gmsv_id, 2);
    const auto bits = std::bit_cast<std::uint64_t>(init.game_value);
    append_le(plain, static_cast<std::uint32_t>(bits), 4);
    append_le(plain, static_cast<std::uint32_t>(bits >> 32U), 4);
    append_le(plain, init.calendar.year, 2);
    plain.insert(plain.end(), {init.calendar.month, init.calendar.day, init.calendar.weekday_index,
                             static_cast<std::uint8_t>(init.players.size()), init.local_slot, init.opaque_header_byte});
    for (const auto& player : init.players) {
        if (player.initial_tile < 0) throw CodecError("original_board_initial_tile_invalid");
        if (player.direction > 3) throw CodecError("original_board_direction_invalid");
        append_le(plain, static_cast<std::uint16_t>(player.lobby_user_id), 2);
        append_le(plain, static_cast<std::uint16_t>(player.initial_tile), 2);
        plain.push_back(player.direction);
        plain.insert(plain.end(), player.skills.begin(), player.skills.end());
        plain.push_back(player.opaque_last_byte);
    }
    plain.insert(plain.end(), init.opaque_suffix.begin(), init.opaque_suffix.end());
    return plain;
}

Bytes encode_original_board_snapshot(const OriginalBoardSnapshot& snapshot) {
    validate_count(snapshot.per_player.size());
    validate_size(12 + 12 * snapshot.per_player.size(), snapshot.opaque_suffix.size());
    if (snapshot.scale == 0) throw CodecError("original_board_scale_invalid");
    Bytes plain;
    plain.reserve(12 + 12 * snapshot.per_player.size() + snapshot.opaque_suffix.size());
    append_le(plain, 0x4004, 2);
    append_le(plain, snapshot.gmsv_id, 2);
    append_le(plain, snapshot.context, 4);
    append_le(plain, snapshot.scale, 4);
    for (const auto& funds : snapshot.per_player) {
        append_le(plain, funds.cash, 4);
        append_le(plain, funds.deposit, 4);
        append_le(plain, funds.tickets, 4);
    }
    plain.insert(plain.end(), snapshot.opaque_suffix.begin(), snapshot.opaque_suffix.end());
    return plain;
}

void validate_original_startup(const OriginalStartup& startup) {
    if (startup.init.gmsv_id != startup.snapshot.gmsv_id)
        throw CodecError("original_board_startup_instance_mismatch");
    if (startup.init.players.size() != startup.snapshot.per_player.size())
        throw CodecError("original_board_startup_count_mismatch");
    encode_original_board_init(startup.init);
    encode_original_board_snapshot(startup.snapshot);
}

Frame original_board_frame(View plain, const OriginalBoardEnvelope& envelope, View filler) {
    if (plain.size() > 509) throw CodecError("original_board_plain_too_large");
    return encode_envelope({envelope.inner_type, envelope.mode, encode_inner(plain, filler), envelope.tail},
                           ClientVersion::legacy);
}

}
