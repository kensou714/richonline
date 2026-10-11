#include "richonline_property_wire.hpp"
#include <bit>

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
RichonlinePropertyUpgradeRequest decode_richonline_property_upgrade_request(View plain) {
    if (plain.size()!=6) throw CodecError("richonline_property_upgrade_request_size");
    if (read_le(plain.first(2))!=0x21) throw CodecError("richonline_property_upgrade_request_opcode");
    if (plain[4]>1) throw CodecError("richonline_property_upgrade_accept_invalid");
    return {static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),plain[4]==1,plain[5]};
}
Bytes richonline_property_upgrade_response(std::uint16_t game_id, bool accept) {
    Bytes plain;
    plain.reserve(5);
    append_le(plain,0x4021,2);
    append_le(plain,game_id,2);
    plain.push_back(accept ? 1 : 0);
    return plain;
}
RichonlinePropertyBuildingRequest decode_richonline_property_building_request(View plain) {
    if(plain.size()!=6) throw CodecError("richonline_property_building_request_size");
    if(read_le(plain.first(2))!=0x23) throw CodecError("richonline_property_building_request_opcode");
    const auto kind=std::bit_cast<std::int8_t>(plain[4]);
    if(kind!=-1 && (kind<2 || kind>6)) throw CodecError("richonline_property_building_kind_invalid");
    return {static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),kind,plain[5]};
}
Bytes richonline_property_building_response(std::uint16_t game_id,std::int8_t kind) {
    if(kind!=-1 && (kind<2 || kind>6)) throw CodecError("richonline_property_building_kind_invalid");
    Bytes plain;
    plain.reserve(5);
    append_le(plain,0x4025,2);
    append_le(plain,game_id,2);
    plain.push_back(static_cast<std::uint8_t>(kind));
    return plain;
}
}
