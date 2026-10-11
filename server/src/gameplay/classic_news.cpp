#include "richonline_classic_news.hpp"
#include "richonline_boss_landing.hpp"
#include "richonline_shop_catalog.hpp"
#include "richonline_motion_card.hpp"
#include "lua_wire.hpp"
#include <algorithm>
#include <array>
#include <limits>

namespace richnet {
namespace {
// 718DE0只向UI30的来源0数组写这29个槽；7192F0直接按报文索引访问。
// 实际映射为other_10_*，完整索引/纹理/NP文件证据见classic-news-initialization.json。
constexpr std::array<std::int16_t,29> news_pictures{
    1,2,5,6,8,9,10,14,15,17,23,26,27,29,30,31,33,39,40,43,44,45,46,48,49,50,51,52,53};
void validate_context(const RichonlineLandingContext& context) {
    if(context.game_mode!=0 || context.actor_slot>=4 || context.synthetic_actor || context.static_type!=1 ||
        context.position<0 || context.property_ref!=-1 || context.road_degree==0 || context.road_degree>4 ||
        !context.actor_status.possession || richonline_landing_controlled(context.actor_status) ||
        (context.occupied_by_other_actor && !context.collision_resolved && !context.phase6_collision_authorized))
        throw CodecError("richonline_classic_news_context_invalid");
}
}
std::vector<Bytes> prepare_richonline_classic_disaster_news(std::uint16_t game,
    const RichonlineLandingContext& context,const RichonlineClassicMoneyNews& event,
    const RichonlineClassicProperty::Disaster& plan,const std::shared_ptr<LuaServer>& script) {
    validate_context(context);
    const auto& before=plan.before();const auto& after=plan.after();
    const bool pictured=event.opcode!=0x408f;
    if(event.opcode<0x408b || event.opcode>0x408f || event.amount!=0 ||
        event.property!=before.id || before.id<0 || pictured!=event.picture.has_value() ||
        (event.picture && std::ranges::find(news_pictures,*event.picture)==news_pictures.end()) ||
        plan.levels()!=(event.opcode==0x408b ? 1 : 5))
        throw CodecError("richonline_classic_news_parameters_invalid");
    Bytes stop;append_le(stop,0x4013,2);append_le(stop,game,2);
    append_le(stop,static_cast<std::uint16_t>(context.position),2);
    Bytes packet;append_le(packet,event.opcode,2);append_le(packet,game,2);
    if(event.picture) append_le(packet,static_cast<std::uint16_t>(*event.picture),2);
    append_le(packet,static_cast<std::uint16_t>(before.id),2);
    std::vector<Bytes> messages{std::move(stop),std::move(packet)};
    if(script) {
        bool prepared=false;
        const LuaBindings api{{"tile.classic_news.prepare",[&](const LuaValue&) {
            if(prepared) throw CodecError("lua_classic_news_already_prepared");
            prepared=true;
            return LuaValue{{"opcode",event.opcode},{"picture",event.picture.value_or(-1)},
                {"property",before.id},{"sprite",before.sprite_type},{"kind",before.kind},
                {"level",before.level},{"owner",before.owner ? static_cast<int>(*before.owner) : -1}};
        }}};
        const auto result=script->call("tile.land",{{"type",1},{"game_id",game},
            {"position",context.position},{"actor",context.actor_slot},{"classic_news_available",true}},api);
        LuaValue wire=LuaValue::array();
        for(const auto& message:messages) wire.push_back(lua_bytes(View(message)));
        const LuaValue expected{{"kind",after.kind},{"level",after.level},
            {"owner",after.owner ? static_cast<int>(*after.owner) : -1},{"messages",wire}};
        if(!prepared || result!=expected || !result.at("kind").is_number_integer() ||
            !result.at("level").is_number_integer() || !result.at("owner").is_number_integer())
            throw CodecError("lua_classic_news_plan_invalid");
    }
    return messages;
}
RichonlineClassicRainNewsPlan prepare_richonline_classic_rain_news(std::uint16_t game,
    const RichonlineLandingContext& context,std::span<const RichonlineClassicRainActor> before,
    const RichonlineMotionCardRules& rules,const std::shared_ptr<LuaServer>& script) {
    validate_context(context);
    if(before.size()<2 || before.size()>4 || context.actor_slot>=before.size() ||
        !before[context.actor_slot].active || before[context.actor_slot].status!=context.actor_status)
        throw CodecError("richonline_classic_news_roster_invalid");
    if(!rules.stay_turns || rules.stay_turns>127)
        throw CodecError("richonline_classic_rain_duration_invalid");
    RichonlineClassicRainNewsPlan plan{{before.begin(),before.end()},{before.begin(),before.end()},{}};
    LuaValue players=LuaValue::array(),expected_stays=LuaValue::array();
    for(std::size_t slot=0;slot<before.size();++slot) {
        const auto& player=before[slot];
        const auto& raw=player.raw;
        // 未知与-1有不同含义；活动角色四项都必须有已核实的原始值。
        if(player.active && (!raw.hotel1493 || !raw.hospital1494 || !raw.jail1495 || !raw.kidnapped1497))
            throw CodecError("richonline_classic_rain_actor_unknown");
        const bool eligible=player.active && raw.hotel1493==-1 && raw.hospital1494==-1 &&
            raw.jail1495==-1 && raw.kidnapped1497==-1;
        if(eligible) plan.after[slot].status.stay=rules.stay_turns;
        players.push_back({{"active",player.active},{"hotel",raw.hotel1493.value_or(-1)},
            {"hospital",raw.hospital1494.value_or(-1)},{"jail",raw.jail1495.value_or(-1)},
            {"kidnapped",raw.kidnapped1497.value_or(-1)},{"stay",player.status.stay}});
        expected_stays.push_back(plan.after[slot].status.stay);
    }
    Bytes stop;append_le(stop,0x4013,2);append_le(stop,game,2);
    append_le(stop,static_cast<std::uint16_t>(context.position),2);
    Bytes packet;append_le(packet,0x4072,2);append_le(packet,game,2);
    plan.messages={std::move(stop),std::move(packet)};
    if(script) {
        bool prepared=false;
        const LuaBindings api{{"tile.classic_news.prepare",[&](const LuaValue&) {
            if(prepared) throw CodecError("lua_classic_news_already_prepared");
            prepared=true;
            return LuaValue{{"opcode",0x4072},{"duration",rules.stay_turns},{"players",players}};
        }}};
        const auto result=script->call("tile.land",{{"type",1},{"game_id",game},
            {"position",context.position},{"actor",context.actor_slot},{"classic_news_available",true}},api);
        LuaValue messages=LuaValue::array();
        for(const auto& message:plan.messages) messages.push_back(lua_bytes(View(message)));
        const LuaValue expected{{"stays",expected_stays},{"messages",messages}};
        if(!prepared || result!=expected) throw CodecError("lua_classic_news_plan_invalid");
        for(const auto& stay:result.at("stays"))
            if(!stay.is_number_integer()) throw CodecError("lua_classic_news_plan_invalid");
    }
    return plan;
}
RichonlineClassicCardSaleNewsPlan prepare_richonline_classic_card_sale_news(std::uint16_t game,
    const RichonlineLandingContext& context,const RichonlineGameFundsSnapshot& before,
    const RichonlineChanceInventory& inventory,const RichonlineShopCatalog& catalog,
    const std::shared_ptr<LuaServer>& script) {
    validate_context(context);
    constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    if(before.funds.tickets>maximum) throw CodecError("richonline_classic_news_balance_invalid");
    auto after=before.funds;
    LuaValue slots=LuaValue::array(),cleared=LuaValue::array();
    for(const auto& slot:inventory) {
        if((slot.card_id==-1 && slot.count!=0) || (slot.card_id!=-1 && (slot.card_id<1 || slot.count<1)))
            throw CodecError("richonline_classic_news_inventory_invalid");
        // 无明确资源价格时拒绝整笔，不跳过该槽或把未知价格当零。
        const auto price=slot.card_id==-1 ? 0U : catalog.price(slot.card_id);
        if(price>maximum-after.tickets) throw CodecError("richonline_classic_news_tickets_overflow");
        after.tickets+=price;
        slots.push_back({{"card",slot.card_id},{"count",slot.count},{"price",price}});
        cleared.push_back({{"card",-1},{"count",0}});
    }
    Bytes stop;append_le(stop,0x4013,2);append_le(stop,game,2);
    append_le(stop,static_cast<std::uint16_t>(context.position),2);
    Bytes packet;append_le(packet,0x4078,2);append_le(packet,game,2);
    RichonlineClassicCardSaleNewsPlan plan{{context.actor_slot,before,after},inventory,{},
        after.tickets-before.funds.tickets,{std::move(stop),std::move(packet)}};
    if(script) {
        bool prepared=false;
        const LuaBindings api{{"tile.classic_news.prepare",[&](const LuaValue&) {
            if(prepared) throw CodecError("lua_classic_news_already_prepared");
            prepared=true;
            return LuaValue{{"opcode",0x4078},{"tickets",before.funds.tickets},{"slots",slots}};
        }}};
        const auto result=script->call("tile.land",{{"type",1},{"game_id",game},
            {"position",context.position},{"actor",context.actor_slot},{"classic_news_available",true}},api);
        LuaValue messages=LuaValue::array();
        for(const auto& message:plan.messages) messages.push_back(lua_bytes(View(message)));
        const LuaValue expected{{"tickets",after.tickets},{"inventory",cleared},{"messages",messages}};
        if(!prepared || result!=expected || !result.at("tickets").is_number_integer())
            throw CodecError("lua_classic_news_plan_invalid");
        for(const auto& slot:result.at("inventory"))
            if(!slot.at("card").is_number_integer() || !slot.at("count").is_number_integer())
                throw CodecError("lua_classic_news_plan_invalid");
    }
    return plan;
}
RichonlineClassicSavingsNewsPlan prepare_richonline_classic_savings_news(std::uint16_t game,
    const RichonlineLandingContext& context,const RichonlineClassicMoneyNews& event,
    std::span<const RichonlineGameFundsSnapshot> before,std::span<const std::uint8_t> active,
    const std::shared_ptr<LuaServer>& script) {
    validate_context(context);
    if(event.opcode!=0x406f || event.property || event.amount>32767 || !event.picture ||
        std::ranges::find(news_pictures,*event.picture)==news_pictures.end())
        throw CodecError("richonline_classic_news_parameters_invalid");
    if(before.size()<2 || before.size()>4 || active.size()!=before.size() ||
        context.actor_slot>=before.size() || active[context.actor_slot]!=1 ||
        std::ranges::any_of(active,[](auto value){return value>1;}))
        throw CodecError("richonline_classic_news_roster_invalid");
    constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    std::uint32_t highest=0;
    for(std::size_t slot=0;slot<before.size();++slot) {
        const auto& funds=before[slot].funds;
        if(!funds.deposit || static_cast<std::uint64_t>(funds.cash)+*funds.deposit>maximum)
            throw CodecError("richonline_classic_news_balance_invalid");
        if(active[slot]) highest=std::max(highest,*funds.deposit);
    }
    RichonlineClassicSavingsNewsPlan plan;
    LuaValue players=LuaValue::array(),expected_funds=LuaValue::array();
    for(std::uint8_t slot=0;slot<before.size();++slot) {
        auto after=before[slot].funds;
        if(active[slot] && *after.deposit==highest) {
            if(event.amount>maximum-after.cash-*after.deposit)
                throw CodecError("richonline_classic_news_income_overflow");
            after.cash+=event.amount;plan.recipients.push_back(slot);
        }
        plan.funds.push_back({slot,before[slot],after});
        players.push_back({{"active",active[slot]!=0},{"cash",before[slot].funds.cash},
            {"deposit",*before[slot].funds.deposit}});
        expected_funds.push_back({{"cash",after.cash},{"deposit",*after.deposit}});
    }
    Bytes stop;append_le(stop,0x4013,2);append_le(stop,game,2);
    append_le(stop,static_cast<std::uint16_t>(context.position),2);
    Bytes packet;append_le(packet,0x406f,2);append_le(packet,game,2);
    append_le(packet,static_cast<std::uint16_t>(*event.picture),2);append_le(packet,event.amount,2);
    plan.messages={std::move(stop),std::move(packet)};
    if(script) {
        bool prepared=false;
        const LuaBindings api{{"tile.classic_news.prepare",[&](const LuaValue&) {
            if(prepared) throw CodecError("lua_classic_news_already_prepared");
            prepared=true;
            return LuaValue{{"opcode",event.opcode},{"amount",event.amount},{"picture",*event.picture},
                {"players",players}};
        }}};
        const auto result=script->call("tile.land",{{"type",1},{"game_id",game},
            {"position",context.position},{"actor",context.actor_slot},{"classic_news_available",true}},api);
        LuaValue messages=LuaValue::array();
        for(const auto& message:plan.messages) messages.push_back(lua_bytes(View(message)));
        const LuaValue expected{{"funds",expected_funds},{"recipients",plan.recipients},{"messages",messages}};
        if(!prepared || result!=expected) throw CodecError("lua_classic_news_plan_invalid");
        for(const auto& funds:result.at("funds"))
            if(!funds.at("cash").is_number_integer() || !funds.at("deposit").is_number_integer())
                throw CodecError("lua_classic_news_plan_invalid");
        for(const auto& recipient:result.at("recipients"))
            if(!recipient.is_number_integer()) throw CodecError("lua_classic_news_plan_invalid");
    }
    return plan;
}
RichonlineClassicNewsPlan prepare_richonline_classic_money_news(std::uint16_t game,
    const RichonlineLandingContext& context,const RichonlineClassicMoneyNews& event,
    const RichonlineGameFundsSnapshot& before,std::uint32_t fines,
    const std::shared_ptr<LuaServer>& script) {
    validate_context(context);
    bool income=false,pictured=false;
    switch(event.opcode) {
    case 0x406d: income=true;break;
    case 0x406e: income=true;pictured=true;break;
    case 0x4070: case 0x4073: case 0x4074: case 0x4075: case 0x4076: case 0x4079: case 0x407c: break;
    case 0x4071: case 0x4077: case 0x407a: case 0x407b: case 0x407d: case 0x407e:
    case 0x4094: case 0x4095: pictured=true;break;
    default: throw CodecError("richonline_classic_news_opcode_unsupported");
    }
    if(event.property || event.amount>32767 || pictured!=event.picture.has_value() ||
        (event.picture && std::ranges::find(news_pictures,*event.picture)==news_pictures.end()))
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
