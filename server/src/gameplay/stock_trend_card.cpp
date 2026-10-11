#include "richonline_stock.hpp"
#include "richonline_player_cards.hpp"
#include "lua_wire.hpp"
#include <algorithm>
#include <limits>

namespace richnet {
RichonlineStockMarket::TrendCard RichonlineStockMarket::prepare_trend_card(View request,
    std::uint16_t calendar,std::span<const std::uint8_t> active,const RichonlinePlayerCards& cards) const {
    if(request.size()<6) throw CodecError("richonline_stock_trend_request_invalid");
    const auto opcode=read_le(request.first(2));
    const bool single=opcode==146 || opcode==147;
    if(opcode<146 || opcode>149 || request.size()!=(single ? 8U : 6U) ||
        read_le(request.subspan(2,2))!=calendar || request[4]>=8 || request[5]!=0)
        throw CodecError("richonline_stock_trend_request_invalid");
    const auto actor=cards.actor_slot();
    if(cards.game_mode()!=0 || cards.game_id()!=game_ || active.size()!=ledger_->actor_count() ||
        active.size()<2 || active.size()>4 || actor>=active.size() || !active[actor] || restricted_ ||
        std::ranges::any_of(active,[](auto value){return value>1;}))
        throw CodecError("richonline_stock_trend_context_invalid");
    if(revision_==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_stock_revision_exhausted");
    const auto target=single ? read_le(request.subspan(6,2)) : 0U;
    if(target>=quotes_.size()) throw CodecError("richonline_stock_slot_invalid");
    const auto id=static_cast<std::int16_t>(1119+opcode-146);
    const auto consumed=cards.prepare_consumption(static_cast<std::int8_t>(request[4]),id);
    if(!consumed) throw CodecError("richonline_stock_trend_card_not_owned");
    TrendCard plan;
    plan.owner_=this;plan.cards_=&cards;plan.revision_=revision_;
    plan.inventory_before_=consumed->source_inventory;plan.inventory_after_=consumed->remaining_inventory;
    plan.active_.assign(active.begin(),active.end());plan.trends_=trends_;
    const auto direction=static_cast<std::int8_t>(opcode==146 || opcode==148 ? 1 : -1);
    for(std::size_t slot=0;slot<quotes_.size();++slot) if(!single || slot==target) {
        // 扣卡前先证明三次变化都能写入正float，避免成功用卡后因溢出永久卡住行情。
        auto price=quotes_[slot].price;
        for(unsigned wave=0;wave<3;++wave) price=next_trend_price(price,direction);
        plan.trends_[slot]={direction,3};
    }
    append_le(plan.response_,0x40e2+opcode-146,2);append_le(plan.response_,game_,2);
    plan.response_.insert(plan.response_.end(),{request[4],0});
    if(single) append_le(plan.response_,target,2);
    if(script_) {
        unsigned step=0;bool invalid=false;
        const auto reject=[&]() -> LuaValue {invalid=true;throw CodecError("lua_stock_trend_plan_invalid");};
        const LuaBindings bindings{
            {"card.prepare",[&](const LuaValue& args) {
                if(step!=0 || args!=LuaValue{{"card",id}} || !args.at("card").is_number_integer()) return reject();
                ++step;return LuaValue{{"slot",request[4]},{"bank",0}};
            }},
            {"stock.trend_snapshot",[&](const LuaValue&) {
                if(step!=1) return reject();
                ++step;auto rows=LuaValue::array();
                for(std::size_t slot=0;slot<quotes_.size();++slot)
                    rows.push_back({{"direction",trends_[slot].direction},{"remaining",trends_[slot].remaining}});
                return rows;
            }},
            {"stock.prepare_trends",[&](const LuaValue& args) {
                auto expected=LuaValue::array();
                for(std::size_t slot=0;slot<quotes_.size();++slot)
                    expected.push_back({{"direction",plan.trends_[slot].direction},{"remaining",plan.trends_[slot].remaining}});
                if(step!=2 || args!=LuaValue{{"trends",expected}}) return reject();
                for(const auto& row:args.at("trends"))
                    if(!row.at("direction").is_number_integer() || !row.at("remaining").is_number_integer()) return reject();
                ++step;return LuaValue{};
            }}
        };
        const auto result=script_->call("game.action",{{"payload",lua_bytes(request)},{"opcode",opcode},
            {"mode",0},{"map",std::string(cards.map_name())},{"actor",actor},{"calendar",calendar},{"game_id",game_}},bindings);
        if(invalid || step!=3 || !result.is_array() || result.size()!=1 || !result[0].is_string() ||
            lua_bytes(result[0])!=plan.response_) throw CodecError("lua_stock_trend_response_invalid");
    }
    return plan;
}
bool RichonlineStockMarket::commit(const TrendCard& plan,std::span<const std::uint8_t> active,
    RichonlinePlayerCards& cards) noexcept {
    if(plan.owner_!=this || plan.cards_!=&cards || revision_!=plan.revision_ ||
        revision_==std::numeric_limits<std::uint64_t>::max() || !std::ranges::equal(active,plan.active_) ||
        cards.inventory()!=plan.inventory_before_) return false;
    cards.commit_inventory(plan.inventory_after_);trends_=plan.trends_;++revision_;return true;
}
}
