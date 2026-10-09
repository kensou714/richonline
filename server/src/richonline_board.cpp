#include "richonline_board.hpp"

#include <bit>
#include <chrono>
#include <set>

namespace richnet {
Bytes encode_richonline_board_init(const RichonlineBoardInit& init) {
    const auto count = init.participants.size();
    if (count == 0 || count > 8) throw CodecError("richonline_board_slot_count_invalid");
    if (init.local_slot >= count || init.participants[init.local_slot].lobby_identity < 0)
        throw CodecError("richonline_board_local_identity_invalid");
    const std::chrono::year_month_day date{std::chrono::year{init.year},
        std::chrono::month{init.month}, std::chrono::day{init.day}};
    if (!date.ok() || init.weekday < 1 || init.weekday > 7)
        throw CodecError("richonline_board_calendar_invalid");
    std::set<std::int16_t> identities;
    for (const auto& participant : init.participants) {
        if (participant.lobby_identity < -1 || participant.position < 0 || participant.direction > 3)
            throw CodecError("richonline_board_participant_unsupported");
        if (participant.lobby_identity >= 0 && !identities.insert(participant.lobby_identity).second)
            throw CodecError("richonline_board_duplicate_identity");
    }
    // New-client 0x65B450 reads a 20-byte header followed by 16-byte participant records.
    Bytes output;
    append_le(output, 0x4000, 2);
    append_le(output, init.game_server_id, 2);
    output.insert(output.end(), init.opaque_f64.begin(), init.opaque_f64.end());
    append_le(output, std::bit_cast<std::uint16_t>(init.year), 2);
    output.push_back(init.month);
    output.push_back(init.day);
    output.push_back(init.weekday);
    output.push_back(static_cast<std::uint8_t>(count));
    output.push_back(init.local_slot);
    output.push_back(init.opaque_header_byte);
    for (const auto& participant : init.participants) {
        append_le(output, std::bit_cast<std::uint16_t>(participant.lobby_identity), 2);
        append_le(output, std::bit_cast<std::uint16_t>(participant.position), 2);
        output.push_back(participant.direction);
        for (const auto cap : participant.building_skill_caps) output.push_back(std::bit_cast<std::uint8_t>(cap));
        output.push_back(participant.opaque_trailing);
    }
    return output;
}

Bytes encode_richonline_board_snapshot(const RichonlineBoardSnapshot& snapshot) {
    if (snapshot.slots.empty() || snapshot.slots.size() > 8)
        throw CodecError("richonline_board_snapshot_count_invalid");
    Bytes output;
    append_le(output, 0x4004, 2);
    append_le(output, snapshot.game_server_id, 2);
    append_le(output, snapshot.calendar_counter, 4);
    append_le(output, snapshot.monetary_scale, 4);
    for (const auto& slot : snapshot.slots) {
        append_le(output, slot.cash, 4);
        append_le(output, slot.deposit, 4);
        append_le(output, slot.tickets, 4);
    }
    return output;
}

Frame richonline_board_frame(View plain, RichonlineBoardEnvelope envelope, View filler) {
    return encode_envelope({envelope.tag, envelope.mode, encode_inner(plain, filler), {}}, ClientVersion::richonline);
}
}
