#include "richonline_construction_wire.hpp"
#include <bit>

namespace richnet {
RichonlineConstructionRequest decode_richonline_construction_request(View plain) {
    if (plain.size() != 6) throw CodecError("richonline_construction_request_size");
    if (read_le(plain.first(2)) != 0x0037) throw CodecError("richonline_construction_request_opcode");
    const auto selection = std::bit_cast<std::int8_t>(plain[4]);
    if (selection != -1 && (selection < 10 || selection > 20))
        throw CodecError("richonline_construction_selection_invalid");
    return {static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),selection,plain[5]};
}
Bytes richonline_construction_response(std::uint16_t game_id, std::int8_t resolved_selection) {
    if (resolved_selection < 10 || resolved_selection > 20)
        throw CodecError("richonline_construction_response_selection_invalid");
    Bytes plain;
    plain.reserve(5);
    append_le(plain,0x403d,2);
    append_le(plain,game_id,2);
    plain.push_back(static_cast<std::uint8_t>(resolved_selection));
    return plain;
}
RichonlineUpgradeRequest decode_richonline_upgrade_request(View plain) {
    if (plain.size() != 6) throw CodecError("richonline_upgrade_request_size");
    if (read_le(plain.first(2)) != 0x0038) throw CodecError("richonline_upgrade_request_opcode");
    if (plain[4] > 1) throw CodecError("richonline_upgrade_accept_invalid");
    return {static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),plain[4] == 1,plain[5]};
}
Bytes richonline_upgrade_response(std::uint16_t game_id, bool accept) {
    Bytes plain;
    plain.reserve(5);
    append_le(plain,0x403e,2);
    append_le(plain,game_id,2);
    plain.push_back(accept ? 1 : 0);
    return plain;
}
RichonlineConstructionRequest decode_richonline_research_request(View plain) {
    if(plain.size()!=6) throw CodecError("richonline_research_request_size");
    if(read_le(plain.first(2))!=0x39) throw CodecError("richonline_research_request_opcode");
    const auto selection=std::bit_cast<std::int8_t>(plain[4]);
    if(selection!=-1 && (selection<1 || selection>7)) throw CodecError("richonline_research_selection_invalid");
    return {static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),selection,plain[5]};
}
Bytes richonline_research_response(std::uint16_t game_id,std::int8_t selection) {
    if(selection!=-1 && (selection<1 || selection>7)) throw CodecError("richonline_research_selection_invalid");
    Bytes plain; append_le(plain,0x403f,2); append_le(plain,game_id,2);
    plain.push_back(static_cast<std::uint8_t>(selection)); return plain;
}
}
