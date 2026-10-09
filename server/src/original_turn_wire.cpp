#include "original_turn_wire.hpp"

namespace richnet {
namespace {
Bytes header(std::uint16_t opcode, std::uint16_t instance) {
    Bytes plain;
    append_le(plain,opcode,2);
    append_le(plain,instance,2);
    return plain;
}
}
Bytes encode_original_turn_start(const OriginalTurnStart& turn) {
    if (turn.current_slot >= 8 || turn.round_start_slot >= 8) throw CodecError("original_turn_slot_invalid");
    if (turn.opaque_suffix.size() > 502) throw CodecError("original_turn_plain_too_large");
    auto plain = header(0x4010,turn.instance);
    plain.insert(plain.end(),{turn.current_slot,turn.round_start_slot,0});
    plain.insert(plain.end(),turn.opaque_suffix.begin(),turn.opaque_suffix.end());
    return plain;
}
Bytes encode_original_boss_turn_resume(const OriginalBossTurnResume& resume) {
    if (resume.opaque_suffix.size() > 503) throw CodecError("original_turn_plain_too_large");
    auto plain = header(0x420f,resume.instance);
    append_le(plain,0xffff,2);
    plain.insert(plain.end(),resume.opaque_suffix.begin(),resume.opaque_suffix.end());
    return plain;
}
Bytes encode_original_initial_cards(const OriginalInitialCards& cards) {
    if (cards.owner < 0 || cards.owner >= 8) throw CodecError("original_initial_cards_owner_invalid");
    if (cards.opaque_suffix.size() > 479) throw CodecError("original_turn_plain_too_large");
    auto plain = header(0x4019,cards.instance);
    append_le(plain,static_cast<std::uint16_t>(cards.owner),2);
    for (const auto& slot : cards.slots) {
        validate_original_card_slot(slot);
        append_le(plain,static_cast<std::uint16_t>(slot.id),2);
        append_le(plain,static_cast<std::uint16_t>(slot.count),2);
        plain.insert(plain.end(),slot.opaque.begin(),slot.opaque.end());
    }
    plain.insert(plain.end(),cards.opaque_suffix.begin(),cards.opaque_suffix.end());
    return plain;
}
}
