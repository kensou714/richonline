#include "richonline_classic_trade.hpp"
#include "lua_wire.hpp"
#include <bit>
#include <limits>

namespace richnet {
std::uint16_t decode_richonline_classic_trade_request(View request) {
    if(request.size()!=4 || read_le(request.first(2))!=0x25)
        throw CodecError("richonline_classic_trade_request_invalid");
    return static_cast<std::uint16_t>(read_le(request.subspan(2,2)));
}
RichonlineClassicTradeResult prepare_richonline_classic_trade(std::uint16_t game_id,
    const RichonlineClassicPropertyState& property,std::uint32_t scale,std::int8_t result,
    std::shared_ptr<LuaServer> script) {
    if(property.sprite_type!=12 || property.kind!=3 || !property.owner || property.level>5 ||
        (result!=-1 && (result<1 || result>6)) || scale>std::numeric_limits<std::int32_t>::max())
        throw CodecError("richonline_classic_trade_context_invalid");
    // 7E4360每次乘法取低32位；涨价先翻倍，之后付款分支才处理财神/穷神。
    auto amount=scale*property.level*600U*static_cast<std::uint32_t>(result);
    if(property.price_rise_days) amount*=2U;
    const auto quote=result==-1 ? 0 : std::bit_cast<std::int32_t>(amount);
    if(quote<0) throw CodecError("richonline_classic_trade_negative_unsupported");
    Bytes packet;append_le(packet,0x4027,2);append_le(packet,game_id,2);
    packet.push_back(static_cast<std::uint8_t>(result));
    if(script) {
        const auto plan=script->call("property.classic_trade",{{"game_id",game_id},{"level",property.level},
            {"scale",scale},{"price_rise_days",property.price_rise_days},{"result",result}});
        const LuaValue expected{{"quote",quote},{"message",lua_bytes(View(packet))}};
        if(plan!=expected || !plan.at("quote").is_number_integer())
            throw CodecError("lua_classic_trade_plan_invalid");
    }
    return {result,quote,std::move(packet)};
}
}
