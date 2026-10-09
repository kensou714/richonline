#include "richonline_controlled_dice.hpp"
#include <bit>

namespace richnet {
namespace {
void validate_inventory(std::int8_t slot, std::int8_t bank) {
    if (slot < 0 || slot > 7) throw CodecError("richonline_controlled_dice_slot_invalid");
    if (bank != 0) throw CodecError("richonline_controlled_dice_bank_unsupported");
}
void validate_die(std::uint8_t die) {
    if (die < 1 || die > 6) throw CodecError("richonline_controlled_dice_die_invalid");
}
}

RichonlineControlledDiceRequest parse_richonline_controlled_dice_request(View plain) {
    if (plain.size() < 2) throw CodecError("richonline_controlled_dice_length_invalid");
    const auto opcode = read_le(plain.first(2));
    switch (opcode) {
    case 103: {
        if (plain.size() != 12) throw CodecError("richonline_controlled_dice_length_invalid");
        const auto slot = std::bit_cast<std::int8_t>(plain[4]);
        const auto bank = std::bit_cast<std::int8_t>(plain[5]);
        validate_inventory(slot,bank);
        validate_die(plain[6]);
        if (read_le(plain.subspan(8,4)) != 0)
            throw CodecError("richonline_controlled_dice_constructor_extension_unknown");
        return RichonlineCardDiceRequest103{
            static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),slot,bank,plain[6],plain[7]};
    }
    case 22:
        if (plain.size() != 6) throw CodecError("richonline_controlled_dice_length_invalid");
        validate_die(plain[4]);
        return RichonlinePaidDiceRequest22{
            static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),plain[4],plain[5]};
    default:
        throw CodecError("richonline_controlled_dice_opcode_unsupported");
    }
}

Bytes encode_richonline_card_used40b7(const RichonlineCardUsed40B7& used) {
    validate_inventory(used.inventory_slot,used.inventory_bank);
    Bytes result;
    append_le(result,0x40b7,2);
    append_le(result,used.game_server_id,2);
    result.push_back(std::bit_cast<std::uint8_t>(used.inventory_slot));
    result.push_back(std::bit_cast<std::uint8_t>(used.inventory_bank));
    return result;
}

Bytes encode_richonline_dice_recovery400b(std::uint16_t game_server_id) {
    Bytes result;
    append_le(result,0x400b,2);
    append_le(result,game_server_id,2);
    result.push_back(1);
    return result;
}
}
