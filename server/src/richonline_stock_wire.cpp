#include "richonline_stock_wire.hpp"

namespace richnet {
RichonlineStockRequest decode_richonline_stock_request(View plain) {
    if(plain.size()!=6) throw CodecError("richonline_stock_request_size");
    const auto opcode=read_le(plain.first(2));
    if(opcode!=0x200 && opcode!=0x201) throw CodecError("richonline_stock_request_opcode");
    const auto slot=read_le(plain.subspan(2,2)),quantity=read_le(plain.subspan(4,2));
    if(slot>=10 || quantity==0 || quantity>32767) throw CodecError("richonline_stock_request_fields_invalid");
    return {opcode==0x200 ? RichonlineStockAction::buy : RichonlineStockAction::sell,
        static_cast<std::uint16_t>(slot),static_cast<std::uint16_t>(quantity)};
}
}
