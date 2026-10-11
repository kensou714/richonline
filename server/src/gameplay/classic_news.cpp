#include "richonline_classic_news.hpp"
#include "richonline_boss_landing.hpp"
#include "lua_wire.hpp"
#include <algorithm>
#include <limits>

namespace richnet {
RichonlineClassicNewsPlan prepare_richonline_classic_money_news(std::uint16_t game,
    const RichonlineLandingContext& context,const RichonlineClassicMoneyNews& event,
    const RichonlineGameFundsSnapshot& before,std::uint32_t fines,
    std::span<const std::int16_t> available_pictures,const std::shared_ptr<LuaServer>& script) {
    if(context.game_mode!=0 || context.actor_slot>=4 || context.synthetic_actor || context.static_type!=1 ||
        context.position<0 || context.property_ref!=-1 || context.road_degree==0 || context.road_degree>4 ||
        !context.actor_status.possession || richonline_landing_controlled(context.actor_status) ||
        (context.occupied_by_other_actor && !context.collision_resolved && !context.phase6_collision_authorized))
        throw CodecError("richonline_classic_news_context_invalid");
    bool income=false,pictured=false;
    switch(event.opcode) {
    case 0x406d: income=true;break;
    case 0x406e: income=true;pictured=true;break;
    case 0x4070: case 0x4073: case 0x4074: case 0x4075: case 0x4076: case 0x4079: case 0x407c: break;
    case 0x4071: case 0x4077: case 0x407a: case 0x407b: case 0x407d: case 0x407e:
    case 0x4094: case 0x4095: pictured=true;break;
    default: throw CodecError("richonline_classic_news_opcode_unsupported");
    }
    if(event.amount>32767 || pictured!=event.picture.has_value() ||
        (event.picture && (*event.picture<0 || *event.picture>=100 ||
            std::ranges::find(available_pictures,*event.picture)==available_pictures.end())))
        throw CodecError("richonline_classic_news_parameters_invalid");
    constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    if(!before.funds.deposit || static_cast<std::uint64_t>(before.funds.cash)+*before.funds.deposit>maximum ||
        fines>maximum || (!income && event.amount>maximum-fines))
        throw CodecError("richonline_classic_news_balance_invalid");
    auto after=before.funds;
    const auto total=after.cash+*after.deposit;
    const bool bankrupt=!income && total<=event.amount;
    if(income) {
        if(event.amount>maximum-total) throw CodecError("richonline_classic_news_income_overflow");
        after.cash+=event.amount;
    } else {
        const auto from_cash=std::min(after.cash,event.amount);
        after.cash-=from_cash;
        *after.deposit-=std::min(*after.deposit,event.amount-from_cash);
    }
    // 693CE0累计的是报文完整金额，破产时也不按实际可扣余额缩减。
    const auto fines_after=income ? fines : fines+event.amount;
    Bytes stop;append_le(stop,0x4013,2);append_le(stop,game,2);
    append_le(stop,static_cast<std::uint16_t>(context.position),2);
    Bytes packet;append_le(packet,event.opcode,2);append_le(packet,game,2);
    if(event.picture) append_le(packet,static_cast<std::uint16_t>(*event.picture),2);
    append_le(packet,event.amount,2);
    RichonlineClassicNewsPlan plan{{context.actor_slot,before,after},fines,fines_after,bankrupt,
        {std::move(stop),std::move(packet)}};
    if(script) {
        const auto request=LuaValue{{"opcode",event.opcode},{"amount",event.amount},
            {"picture",event.picture ? static_cast<int>(*event.picture) : -1},
            {"cash",before.funds.cash},{"deposit",*before.funds.deposit},{"fines",fines}};
        bool prepared=false;
        const LuaBindings api{{"tile.classic_news.prepare",[&](const LuaValue&) {
            if(prepared) throw CodecError("lua_classic_news_already_prepared");
            prepared=true;return request;
        }}};
        const auto result=script->call("tile.land",{{"type",1},{"game_id",game},
            {"position",context.position},{"actor",context.actor_slot},{"classic_news_available",true}},api);
        LuaValue messages=LuaValue::array();
        for(const auto& message:plan.messages) messages.push_back(lua_bytes(View(message)));
        const LuaValue expected{{"cash",after.cash},{"deposit",*after.deposit},{"fines",fines_after},
            {"bankrupt",bankrupt},{"messages",std::move(messages)}};
        if(!prepared || result!=expected || !result.at("cash").is_number_integer() ||
            !result.at("deposit").is_number_integer() || !result.at("fines").is_number_integer())
            throw CodecError("lua_classic_news_plan_invalid");
    }
    return plan;
}
}
