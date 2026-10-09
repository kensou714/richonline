#include "original_god_wire.hpp"
#include <bit>

namespace richnet {
OriginalWealthChoice parse_original_wealth_choice(View plain) {
    if (plain.size() != 6) throw CodecError("original_wealth_request_length_invalid");
    if (read_le(plain.first(2)) != 34) throw CodecError("original_wealth_opcode_invalid");
    if (plain[4] != 1) throw CodecError("original_wealth_action_invalid");
    return {static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),plain[4],plain[5]};
}
Bytes encode_original_wealth_result(std::uint16_t instance, std::int16_t amount, bool bankruptcy_wait) {
    if (amount < 0) throw CodecError("original_wealth_amount_invalid");
    Bytes bytes; append_le(bytes,0x4022,2); append_le(bytes,instance,2);
    append_le(bytes,static_cast<std::uint16_t>(amount),2); bytes.push_back(bankruptcy_wait ? 1 : 0);
    return bytes;
}
Bytes encode_original_blessing_result(std::uint16_t instance, std::array<std::int16_t,2> cards) {
    Bytes bytes; append_le(bytes,0x4023,2); append_le(bytes,instance,2);
    for (const auto card : cards) {
        if (card <= 0) throw CodecError("original_blessing_card_invalid");
        append_le(bytes,static_cast<std::uint16_t>(card),2);
    }
    return bytes;
}
Bytes encode_original_misfortune_result(std::uint16_t instance, std::array<std::int8_t,4> slots) {
    Bytes bytes; append_le(bytes,0x4024,2); append_le(bytes,instance,2);
    for (const auto slot : slots) {
        if (slot < -1 || slot >= 8 || (slots[0] == -1 && slot != -1)) throw CodecError("original_misfortune_slot_invalid");
        bytes.push_back(std::bit_cast<std::uint8_t>(slot));
    }
    return bytes;
}
Bytes encode_original_npc_spawn(std::uint16_t instance, std::int16_t tile, std::uint8_t kind) {
    if (tile < 0 || (kind > 7 && kind != 9 && kind != 32)) throw CodecError("original_npc_spawn_fields_invalid");
    Bytes bytes; append_le(bytes,0x401c,2); append_le(bytes,instance,2);
    append_le(bytes,static_cast<std::uint16_t>(tile),2);
    bytes.insert(bytes.end(),{kind,255,255});
    return bytes;
}
}
