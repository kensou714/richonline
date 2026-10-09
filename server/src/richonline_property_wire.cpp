#include "richonline_property_wire.hpp"

namespace richnet {
RichonlinePropertyRequest decode_richonline_property_request(View plain) {
    if (plain.size() != 12) throw CodecError("richonline_property_request_size");
    if (read_le(plain.first(2)) != 0x20) throw CodecError("richonline_property_request_opcode");
    const auto secondary = read_le(plain.subspan(4,4));
    if (secondary != 0) throw CodecError("richonline_property_secondary_unsupported");
    if (plain[8] > 1) throw CodecError("richonline_property_accept_invalid");
    return {static_cast<std::uint16_t>(read_le(plain.subspan(2,2))), secondary,
        plain[8] == 1, {plain[9],plain[10],plain[11]}};
}
Bytes richonline_property_response(std::uint16_t game_id, bool accept) {
    Bytes plain;
    plain.reserve(5);
    append_le(plain,0x4020,2);
    append_le(plain,game_id,2);
    plain.push_back(accept ? 1 : 0);
    return plain;
}
}
