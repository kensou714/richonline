#include "richonline_room_protocol.hpp"

#include <algorithm>
#include <limits>

namespace richnet {
namespace {
constexpr std::size_t base_size = 128;
constexpr std::size_t edit_prefix_size = 4;
constexpr std::size_t max_extension = max_frame_total - base_size - 16;

std::size_t c_string_end(View bytes, std::size_t offset) {
    const auto tail = bytes.subspan(offset, 32);
    const auto end = std::find(tail.begin(), tail.end(), std::uint8_t{0});
    if (end == tail.end()) throw CodecError(offset == 0 ? "richonline_room_name_unterminated" : "richonline_room_secondary_name_unterminated");
    return static_cast<std::size_t>(end - tail.begin());
}

RichonlineRoomDescription decode_description(View payload, std::uint32_t flag_mask, bool creating) {
    if (payload.size() < base_size) throw CodecError("richonline_room_description_truncated");
    c_string_end(payload, 0);
    c_string_end(payload, 76);
    const auto flags = read_le(payload.subspan(32, 4));
    if ((flags & ~flag_mask) != 0) throw CodecError("richonline_room_flags_unsupported");
    const auto length = read_le(payload.subspan(120, 4));
    const bool has_extension = (flags & 0x40U) != 0;
    if (creating && has_extension != (length != 0)) throw CodecError("richonline_room_data_flag_mismatch");
    if (length > max_extension || base_size + static_cast<std::size_t>(length) != payload.size())
        throw CodecError("richonline_room_data_length_mismatch");
    if (payload[124] != 1 || payload[125] != 0 || payload[126] != 0 || payload[127] != 0)
        throw CodecError("richonline_room_data_marker_invalid");
    RichonlineRoomDescription result{};
    std::copy_n(payload.begin(), base_size, result.record.begin());
    result.extension.assign(payload.begin() + static_cast<std::ptrdiff_t>(base_size), payload.end());
    return result;
}
}

std::uint32_t RichonlineRoomDescription::field(std::size_t offset) const {
    if (offset > record.size() - 4 || offset % 4 != 0) throw CodecError("richonline_room_field_offset_invalid");
    return read_le(View(record).subspan(offset, 4));
}

RichonlineRoomDescription decode_richonline_room_create(View payload) { return decode_description(payload, 0x13c1U, true); }

RichonlineRoomEdit decode_richonline_room_edit(View payload) {
    if (payload.size() < edit_prefix_size) throw CodecError("richonline_room_edit_truncated");
    RichonlineRoomEdit result{};
    result.tag = read_le(payload.first(edit_prefix_size));
    result.description = decode_description(payload.subspan(edit_prefix_size), 0x1340U, false);
    return result;
}

Frame richonline_room_record(std::uint32_t wire_type, const RichonlineRoomDescription& description,
                            RichonlineRoomIdentity identity) {
    if (wire_type != 5 && wire_type != 10) throw CodecError("richonline_room_response_type_invalid");
    if (identity.key > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()) ||
        identity.actor > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()) ||
        identity.slot > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw CodecError("richonline_room_identity_out_of_range");
    Bytes payload;
    payload.reserve(8 + base_size + description.extension.size());
    append_le(payload, identity.key, 4);
    append_le(payload, identity.unknown_prefix, 4);
    payload.insert(payload.end(), description.record.begin(), description.record.begin() + 60);
    append_le(payload, identity.actor, 4);
    append_le(payload, identity.slot, 4);
    append_le(payload, identity.object28, 4);
    append_le(payload, description.field(68), 4);
    payload.insert(payload.end(), description.record.begin() + 76, description.record.begin() + 120);
    if ((description.field(32) & 0x40U) != 0) {
        payload.insert(payload.end(), description.record.begin() + 120, description.record.end());
        payload.insert(payload.end(), description.extension.begin(), description.extension.end());
    }
    return {wire_type, std::move(payload)};
}
}
