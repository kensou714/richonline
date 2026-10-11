#include "richonline_classic_computer.hpp"
#include "lua_server.hpp"
#include <bit>
#include <limits>

namespace richnet {
std::int32_t richonline_classic_computer_quote(const RichonlineClassicPropertyState& property,
    std::uint32_t monetary_scale,std::shared_ptr<LuaServer> script) {
    if(property.sprite_type!=12 || property.kind!=5 || !property.owner || property.level>5 ||
        monetary_scale>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw CodecError("richonline_classic_computer_context_invalid");
    // 7E42F0保留32位乘法回绕，涨价在乘法后翻倍；不借住宅联排或贸易转盘公式。
    auto amount=static_cast<std::uint32_t>(property.level)*150U*monetary_scale;
    if(property.price_rise_days) amount*=2U;
    const auto quote=std::bit_cast<std::int32_t>(amount);
    if(script) {
        const auto result=script->call("property.classic_computer_quote",{{"level",property.level},
            {"scale",monetary_scale},{"price_rise_days",property.price_rise_days}});
        if(!result.is_number_integer() || result!=LuaValue(quote))
            throw CodecError("lua_classic_computer_quote_invalid");
    }
    return quote;
}
}
