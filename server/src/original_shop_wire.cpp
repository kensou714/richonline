#include "original_shop_wire.hpp"
#include <bit>

namespace richnet {
namespace {
Bytes header(std::uint16_t opcode, std::uint16_t instance) {
    Bytes bytes; append_le(bytes,opcode,2); append_le(bytes,instance,2); return bytes;
}
void inventory_slot(std::int8_t slot) {
    if (slot < 0 || slot >= 8) throw CodecError("original_shop_inventory_slot_invalid");
}
void shop_index(std::int8_t index) {
    if (index < -1 || index >= 12) throw CodecError("original_shop_index_invalid");
}
}
OriginalShopRequest parse_original_shop_request(View plain) {
    if (plain.size() < 2) throw CodecError("original_shop_request_length_invalid");
    const auto opcode = read_le(plain.first(2));
    if (opcode != 48 && opcode != 49 && opcode != 50 && opcode != 53) throw CodecError("original_shop_opcode_unsupported");
    if (plain.size() != (opcode == 53 ? 4U : 6U)) throw CodecError("original_shop_request_length_invalid");
    const auto context = static_cast<std::uint16_t>(read_le(plain.subspan(2,2)));
    if (opcode == 53) return OriginalShopRefresh{context};
    const auto index = std::bit_cast<std::int8_t>(plain[4]);
    switch (opcode) {
    case 48: shop_index(index); return OriginalShopChoice{context,index,plain[5]};
    case 49: inventory_slot(index); return OriginalShopSale{context,index,plain[5]};
    case 50: inventory_slot(index); return OriginalCardDiscard{context,index,plain[5]};
    default: throw CodecError("original_shop_opcode_unsupported");
    }
}
Bytes encode_original_shop_stock(const OriginalShopStock& stock) {
    auto bytes = header(0x4030,stock.instance);
    for (const auto& slot : stock.slots) {
        validate_original_card_slot(slot);
        append_le(bytes,std::bit_cast<std::uint16_t>(slot.id),2);
        append_le(bytes,std::bit_cast<std::uint16_t>(slot.count),2);
        bytes.insert(bytes.end(),slot.opaque.begin(),slot.opaque.end());
    }
    bytes.push_back(stock.refresh ? 1 : 0);
    return bytes;
}
Bytes encode_original_shop_choice(std::uint16_t instance, std::int8_t index) {
    shop_index(index);
    auto bytes = header(0x4031,instance); bytes.push_back(std::bit_cast<std::uint8_t>(index)); return bytes;
}
Bytes encode_original_shop_sale(std::uint16_t instance, std::int8_t slot) {
    inventory_slot(slot);
    auto bytes = header(0x4032,instance); bytes.push_back(static_cast<std::uint8_t>(slot)); return bytes;
}
Bytes encode_original_card_discard(std::uint16_t instance, std::uint8_t slot, std::uint8_t owner) {
    if (slot >= 8 || owner >= 8) throw CodecError("original_card_discard_slot_invalid");
    auto bytes = header(0x4033,instance); bytes.push_back(slot); bytes.push_back(owner); return bytes;
}
Bytes encode_original_card_grant(std::uint16_t instance, std::int16_t card) {
    if (card < 0) throw CodecError("original_card_grant_id_invalid");
    auto bytes = header(0x4029,instance); append_le(bytes,static_cast<std::uint16_t>(card),2); return bytes;
}
}
