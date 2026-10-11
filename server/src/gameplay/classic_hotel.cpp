#include "richonline_classic_hotel.hpp"
#include "original_game_values.hpp"
#include "lua_wire.hpp"
#include <bit>
#include <limits>

namespace richnet {
RichonlineClassicHotelRules RichonlineClassicHotelRules::load(const std::filesystem::path& root) {
    const auto days=load_original_game_values(root/"Data"/"GValue.kpd").require(1);
    if(days<1 || days>127) throw CodecError("richonline_classic_hotel_duration_invalid");
    return {static_cast<std::int8_t>(days)};
}
std::uint16_t decode_richonline_classic_hotel_request(View request) {
    if(request.size()!=4 || read_le(request.first(2))!=0x26)
        throw CodecError("richonline_classic_hotel_request_invalid");
    return static_cast<std::uint16_t>(read_le(request.subspan(2,2)));
}
RichonlineClassicTradeResult prepare_richonline_classic_hotel(std::uint16_t game_id,
    const RichonlineClassicPropertyState& property,std::uint32_t scale,std::int8_t result,
    std::shared_ptr<LuaServer> script) {
    if(property.sprite_type!=12 || property.kind!=4 || !property.owner || property.level>5 ||
        (result!=-1 && (result<1 || result>6)) || scale>std::numeric_limits<std::int32_t>::max())
        throw CodecError("richonline_classic_hotel_context_invalid");
    auto amount=scale*property.level*600U*static_cast<std::uint32_t>(result);
    if(property.price_rise_days) amount*=2U;
    const auto quote=result==-1 ? 0 : std::bit_cast<std::int32_t>(amount);
    if(quote<0) throw CodecError("richonline_classic_hotel_negative_unsupported");
    Bytes packet;append_le(packet,0x4028,2);append_le(packet,game_id,2);
    packet.push_back(static_cast<std::uint8_t>(result));
    if(script) {
        const auto plan=script->call("property.classic_hotel",{{"game_id",game_id},{"level",property.level},
            {"scale",scale},{"price_rise_days",property.price_rise_days},{"result",result}});
        const LuaValue expected{{"quote",quote},{"message",lua_bytes(View(packet))}};
        if(plan!=expected || !plan.at("quote").is_number_integer())
            throw CodecError("lua_classic_hotel_plan_invalid");
    }
    return {result,quote,std::move(packet)};
}
RichonlineClassicHotelVisit prepare_richonline_classic_hotel_visit(const RichonlineRoadTopology& topology,
    std::int16_t road,std::int16_t property,std::shared_ptr<LuaServer> script) {
    const auto& source=topology.cell(road);
    static_cast<void>(topology.cell(property));
    if(!source.walkable || source.property_ref!=property)
        throw CodecError("richonline_classic_hotel_road_invalid");
    const auto width=static_cast<std::int32_t>(topology.width());
    std::int32_t inside=property,heading=-1;
    // 原生后面三个条件是(尚未命中且匹配第一候选)或匹配第二候选，
    // 后者仍可能覆盖之前的方向，且使用被前面分支改写后的inside。
    auto candidate=inside-2*width;
    if(road==candidate || road==candidate-1) {heading=0;inside=road+width;}
    candidate=inside+width;
    if((heading==-1 && road==candidate) || road==candidate-1) {heading=2;inside=road-width;}
    candidate=inside+1;
    if((heading==-1 && road==candidate) || road==candidate-width) {heading=1;inside=road-1;}
    candidate=inside-2;
    if((heading==-1 && road==candidate) || road==candidate-width) {heading=3;inside=road+1;}
    if(heading<0 || inside<0 || inside>std::numeric_limits<std::int16_t>::max())
        throw CodecError("richonline_classic_hotel_geometry_invalid");
    static_cast<void>(topology.cell(static_cast<std::int16_t>(inside)));
    // 拒绝线性+/-1跨行，不把无方向的原生异常情况伪造为合法住店。
    const auto dx=inside%width-road%width,dy=inside/width-road/width;
    const std::array<std::array<int,2>,4> offsets{{{0,1},{-1,0},{0,-1},{1,0}}};
    if(dx!=offsets[static_cast<std::size_t>(heading)][0] || dy!=offsets[static_cast<std::size_t>(heading)][1])
        throw CodecError("richonline_classic_hotel_cross_row");
    if(script) {
        const auto result=script->call("property.classic_hotel_visit",{{"road",road},{"property",property},{"width",width}});
        const LuaValue expected{{"inside",inside},{"heading",heading}};
        if(result!=expected || !result.at("inside").is_number_integer() || !result.at("heading").is_number_integer())
            throw CodecError("lua_classic_hotel_visit_invalid");
    }
    return {property,road,static_cast<std::int16_t>(inside),static_cast<std::uint8_t>(heading)};
}
}
