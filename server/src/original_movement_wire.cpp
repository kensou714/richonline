#include "original_movement_wire.hpp"
#include <bit>
#include <limits>

namespace richnet {
namespace {
void validate_direction(std::int8_t direction) {
    if (direction < -1 || direction > 3) throw CodecError("original_movement_direction_invalid");
}
void validate_tile(std::int16_t tile) {
    if (tile < 0) throw CodecError("original_movement_tile_invalid");
}
Bytes header(std::uint16_t opcode, std::uint16_t gmsv_id) {
    Bytes bytes;
    append_le(bytes, opcode, 2);
    append_le(bytes, gmsv_id, 2);
    return bytes;
}
}
OriginalMovementRequest parse_original_movement_request(View plain) {
    if (plain.size() < 2) throw CodecError("original_movement_request_length_invalid");
    const auto opcode = read_le(plain.first(2));
    if (opcode != 16 && opcode != 17 && opcode != 18 && opcode != 20 && opcode != 52)
        throw CodecError("original_movement_opcode_unsupported");
    if (plain.size() != (opcode == 16 ? 8U : 6U)) throw CodecError("original_movement_request_length_invalid");
    const auto context = static_cast<std::uint16_t>(read_le(plain.subspan(2,2)));
    switch (opcode) {
    case 16: return OriginalRollRequest{context, read_le(plain.subspan(4,4))};
    case 17:
    case 18: {
        const auto tile = std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(read_le(plain.subspan(4,2))));
        validate_tile(tile);
        return OriginalMoveReport{opcode == 17 ? OriginalMoveKind::normal : OriginalMoveKind::special, context, tile};
    }
    case 20: {
        const auto count = std::bit_cast<std::int8_t>(plain[4]);
        if (count < 1 || count > 3) throw CodecError("original_movement_dice_count_invalid");
        return OriginalDiceChoice{context, count, plain[5]};
    }
    case 52: {
        const auto direction = std::bit_cast<std::int8_t>(plain[4]);
        validate_direction(direction);
        return OriginalDirectionChoice{context, direction, plain[5]};
    }
    default: throw CodecError("original_movement_opcode_unsupported");
    }
}
Bytes encode_original_roll_route(const OriginalRollRoute& route) {
    validate_tile(route.start_tile);
    if (route.dice_count < 1 || route.dice_count > 3) throw CodecError("original_movement_dice_count_invalid");
    for (std::size_t index = 0; index < route.dice_count; ++index)
        if (route.faces[index] < 1 || route.faces[index] > 6) throw CodecError("original_movement_faces_invalid");
    if (route.directions.empty() || route.directions.size() > 36) throw CodecError("original_movement_route_length_invalid");
    if (route.gold_charge > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw CodecError("original_movement_gold_charge_invalid");
    auto storage = route.route_storage;
    for (std::size_t i = 0; i < route.directions.size(); ++i) {
        const auto direction = route.directions[i];
        if (direction > 3) throw CodecError("original_movement_direction_invalid");
        const auto shift = static_cast<unsigned>(2 * (i % 4));
        storage[i / 4] = static_cast<std::uint8_t>((storage[i / 4] & ~(3U << shift)) | (static_cast<unsigned>(direction) << shift));
    }
    auto plain = header(0x4011, route.gmsv_id);
    append_le(plain, static_cast<std::uint16_t>(route.start_tile), 2);
    plain.push_back(route.dice_count);
    plain.push_back(static_cast<std::uint8_t>(route.directions.size()));
    plain.insert(plain.end(), route.faces.begin(), route.faces.end());
    plain.insert(plain.end(), storage.begin(), storage.end());
    append_le(plain, route.gold_charge, 4);
    return plain;
}
Bytes encode_original_landing(const OriginalLanding& landing) {
    validate_tile(landing.tile);
    if (landing.opaque_suffix.size() > 503) throw CodecError("original_movement_plain_too_large");
    auto plain = header(0x4013, landing.gmsv_id);
    append_le(plain, static_cast<std::uint16_t>(landing.tile), 2);
    plain.insert(plain.end(), landing.opaque_suffix.begin(), landing.opaque_suffix.end());
    return plain;
}
Bytes encode_original_direction_result(const OriginalDirectionResult& result) {
    validate_direction(result.direction);
    if (result.opaque_suffix.size() > 504) throw CodecError("original_movement_plain_too_large");
    auto plain = header(0x4035, result.gmsv_id);
    plain.push_back(std::bit_cast<std::uint8_t>(result.direction));
    plain.insert(plain.end(), result.opaque_suffix.begin(), result.opaque_suffix.end());
    return plain;
}
}
