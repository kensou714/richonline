#include "richonline_classic_feasts.hpp"
#include "original_options.hpp"
#include "lua_server.hpp"

#include <algorithm>
#include <limits>

namespace richnet {
RichonlineFeastResources RichonlineFeastResources::parse(View decoded) {
    if(decoded.size()!=806) throw CodecError("richonline_feast_resource_size");
    RichonlineFeastResources result;
    for(std::size_t year=0;year<31;++year) for(std::size_t slot=0;slot<13;++slot) {
        const auto offset=(year*13+slot)*2;
        const auto month=decoded[offset],day=decoded[offset+1];
        const std::chrono::year_month_day date{std::chrono::year{static_cast<int>(year)+2004},
            std::chrono::month{month},std::chrono::day{day}};
        if(!date.ok()) throw CodecError("richonline_feast_resource_date");
        result.dates_[year][slot]={month,day};
    }
    return result;
}
RichonlineFeastResources RichonlineFeastResources::load(const std::filesystem::path& root) {
    return parse(load_original_kpd(root/"Data"/"Feast.kpd",806));
}
std::optional<std::uint8_t> RichonlineFeastResources::find(std::chrono::year_month_day date) const {
    const auto year=static_cast<int>(date.year());
    // 客户端跨出资源年份有本机年份回退，未证明同步协议前不能自行外推或静默跳过。
    if(!date.ok() || year<2004 || year>2034) throw CodecError("richonline_feast_date_unsupported");
    const auto& dates=dates_[static_cast<std::size_t>(year-2004)];
    for(std::uint8_t slot=0;slot<dates.size();++slot)
        if(dates[slot][0]==static_cast<unsigned>(date.month()) &&
            dates[slot][1]==static_cast<unsigned>(date.day())) return slot;
    return {};
}
RichonlineClassicFeastPlan prepare_richonline_classic_feast(std::uint8_t slot,std::uint16_t game_id,
    std::span<const std::uint8_t> active,std::span<const RichonlineActorStatus> statuses,
    const RichonlineRawAuthority& raw,const RichonlineGameLedger& ledger,
    std::span<const std::shared_ptr<RichonlinePlayerCards>> cards,
    const RichonlineRouteChooser& random,const std::shared_ptr<LuaServer>& script) {
    const auto count=active.size();
    if(slot>=13 || count<2 || count>4 || statuses.size()!=count || cards.size()!=count ||
        ledger.actor_count()!=count || raw.actor_count()!=count || !random ||
        raw.game().scripted_event83830!=-1)
        throw CodecError("richonline_classic_feast_context_invalid");
    const bool gift=slot==1 || slot==2 || slot==4 || slot==5 || slot==9;
    const auto opcode=gift ? 0x40a0 : slot==3 ? 0x40a1 : 0;
    std::array<std::int16_t,8> gifts;gifts.fill(-1);
    std::array<std::uint8_t,8> luck{};
    auto input=LuaValue::array(),expected=LuaValue::array();
    RichonlineClassicFeastPlan result{slot,{},{}};
    result.changes.reserve(count);
    for(std::uint8_t actor=0;actor<count;++actor) {
        if(active[actor]>1) throw CodecError("richonline_classic_feast_active_invalid");
        if(!active[actor]) continue;
        const auto& hand=cards[actor];
        const auto actor_raw=raw.actor(actor);
        if(!hand || hand->actor_slot()!=actor || hand->game_id()!=game_id || hand->game_mode()!=0 ||
            !statuses[actor].possession || !actor_raw.hospital1494 || !actor_raw.jail1495 ||
            *actor_raw.hospital1494 < -1 || *actor_raw.jail1495 < -1 ||
            (*actor_raw.hospital1494>=0 && *actor_raw.jail1495>=0))
            throw CodecError("richonline_classic_feast_actor_unknown");
        const auto funds=ledger.snapshot(actor);
        RichonlineClassicFeastChange change{actor,funds,funds.funds,hand->inventory(),hand->inventory(),
            statuses[actor],statuses[actor],actor_raw};
        const std::int32_t cash=slot==6 ? 8000 : 0;
        std::int32_t tickets=slot==0 ? 111 : slot==8 ? 55 : slot==11 ? 99 : 0;
        if(slot==3) {
            const auto selected=random(2);
            if(selected>=2) throw CodecError("richonline_classic_feast_random_invalid");
            luck[actor]=static_cast<std::uint8_t>(selected);
            tickets=selected ? 41 : -41;
        }
        if(gift) {
            const auto reward=hand->prepare_random_reward();
            gifts[actor]=reward.card;change.after_inventory=reward.inventory;
        }
        const auto possession=*statuses[actor].possession;
        const bool detach=slot==12 && (possession==1 || possession==2 || possession==6 || possession==7 || possession==18);
        if(detach) {
            richonline_detach_possession(change.after_status);
            // 经典会话以-1表示已知无附身，optional空值保留给未知状态。
            change.after_status.possession=-1;
        }
        if(slot==12) {
            change.after_status.timed_bomb.reset();change.after_status.timed_bomb_owner.reset();
        }
        const auto release=slot==7 && *actor_raw.hospital1494!=-1 ? 1 :
            slot==10 && *actor_raw.jail1495!=-1 ? 2 : 0;
        change.release=static_cast<RichonlineFeastRelease>(release);
        constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
        if(change.after_funds.cash>maximum-static_cast<std::uint32_t>(cash) ||
            change.after_funds.tickets>maximum || (tickets>0 &&
            change.after_funds.tickets>maximum-static_cast<std::uint32_t>(tickets)))
            throw CodecError("richonline_classic_feast_funds_overflow");
        change.after_funds.cash+=static_cast<std::uint32_t>(cash);
        if(tickets<0) change.after_funds.tickets-=std::min(change.after_funds.tickets,static_cast<std::uint32_t>(-tickets));
        else change.after_funds.tickets+=static_cast<std::uint32_t>(tickets);
        input.push_back({{"actor",actor},{"possession",possession},{"hospital",*actor_raw.hospital1494},
            {"jail",*actor_raw.jail1495},{"luck",luck[actor]},{"card",gifts[actor]}});
        expected.push_back({{"actor",actor},{"cash",cash},{"tickets",tickets},{"card",gifts[actor]},
            {"release",release},{"detach",detach},{"clear_bomb",slot==12}});
        result.changes.push_back(std::move(change));
    }
    if(script) {
        const auto plan=script->call("feast.classic",{{"slot",slot},{"actors",input}});
        if(plan!=LuaValue{{"opcode",opcode},{"effects",expected}} || !plan.at("opcode").is_number_integer())
            throw CodecError("lua_classic_feast_plan_invalid");
        for(const auto& effect:plan.at("effects")) for(const auto* key:{"actor","cash","tickets","card","release"})
            if(!effect.at(key).is_number_integer()) throw CodecError("lua_classic_feast_plan_invalid");
    }
    // 固定现金、点券及状态清理已由4010本地排队；只能对等待回复的六槽发包。
    if(opcode) {
        Bytes packet;append_le(packet,opcode,2);append_le(packet,game_id,2);
        if(gift) for(const auto card:gifts) append_le(packet,static_cast<std::uint16_t>(card),2);
        else packet.insert(packet.end(),luck.begin(),luck.end());
        result.messages.push_back(std::move(packet));
    }
    return result;
}
}
