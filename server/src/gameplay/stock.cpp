#include "richonline_stock.hpp"
#include "lua_wire.hpp"
#include <bit>
#include <cmath>
#include <limits>
#include <set>
#include <utility>

namespace richnet {
namespace {
constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
void valid_price(float price) {
    if(!std::isfinite(price) || price<=0) throw CodecError("richonline_stock_price_invalid");
}
void available_revision(std::uint64_t revision) {
    if(revision==std::numeric_limits<std::uint64_t>::max()) throw CodecError("richonline_stock_revision_exhausted");
}
}
RichonlineStockRequest decode_richonline_stock_request(View plain) {
    if(plain.size()!=6) throw CodecError("richonline_stock_request_size");
    const auto opcode=read_le(plain.first(2));
    if(opcode!=0x200 && opcode!=0x201) throw CodecError("richonline_stock_request_opcode");
    const auto slot=read_le(plain.subspan(2,2)),quantity=read_le(plain.subspan(4,2));
    if(slot>=10 || quantity==0 || quantity>32767) throw CodecError("richonline_stock_request_fields_invalid");
    return {opcode==0x200 ? RichonlineStockAction::buy : RichonlineStockAction::sell,
        static_cast<std::uint16_t>(slot),static_cast<std::uint16_t>(quantity)};
}
RichonlineStockMarket::RichonlineStockMarket(std::uint16_t game,std::shared_ptr<RichonlineGameLedger> ledger,
    std::vector<RichonlineStockQuote> quotes,float rise_limit,float fall_limit,std::shared_ptr<LuaServer> script)
    :game_(game),ledger_(std::move(ledger)),script_(std::move(script)),quotes_(std::move(quotes)),
     rise_limit_(rise_limit),fall_limit_(fall_limit) {
    if(!ledger_ || quotes_.empty() || quotes_.size()>10 || !std::isfinite(rise_limit_) ||
        !std::isfinite(fall_limit_) || rise_limit_<=0 || fall_limit_>=0)
        throw CodecError("richonline_stock_market_invalid");
    std::set<std::int32_t> configurations;
    for(const auto& entry:quotes_) {
        valid_price(entry.price);
        if(entry.configuration<0 || !configurations.insert(entry.configuration).second ||
            entry.supply==0 || entry.supply>maximum || !std::isfinite(entry.change_percent))
            throw CodecError("richonline_stock_quote_invalid");
    }
    for(std::size_t actor=0;actor<ledger_->actor_count();++actor)
        if(!ledger_->snapshot(static_cast<std::uint8_t>(actor)).funds.deposit)
            throw CodecError("richonline_stock_deposit_unknown");
}
RichonlineStockHolding RichonlineStockMarket::holding(std::uint8_t actor,std::uint16_t slot) const {
    if(actor>=ledger_->actor_count() || slot>=quotes_.size()) throw CodecError("richonline_stock_holding_invalid");
    return holdings_[actor][slot];
}
RichonlineStockQuote RichonlineStockMarket::quote(std::uint16_t slot) const {
    if(slot>=quotes_.size()) throw CodecError("richonline_stock_slot_invalid");
    return quotes_[slot];
}
void RichonlineStockMarket::set_restricted(bool restricted) {
    if(restricted_==restricted) return;
    available_revision(revision_);restricted_=restricted;++revision_;
}
Bytes RichonlineStockMarket::change_price(std::uint16_t slot,float price) {
    const auto before=quote(slot);valid_price(price);available_revision(revision_);
    float change=(price-before.price)/before.price*100.0F;
    if(!std::isfinite(change)) throw CodecError("richonline_stock_change_invalid");
    // NEW80F2D0只修饰涨跌幅，不把服务器收到的实际价格钳到1..999.99。
    if(change<fall_limit_+0.02F) change=fall_limit_;
    else if(change>rise_limit_-0.02F) change=rise_limit_;
    Bytes response;append_le(response,0x4203,2);append_le(response,game_,2);
    append_le(response,slot,2);append_le(response,0,2);append_le(response,std::bit_cast<std::uint32_t>(price),4);
    quotes_[slot].price=price;quotes_[slot].change_percent=change;++revision_;
    return response;
}
RichonlineStockMarket::Trade RichonlineStockMarket::prepare(std::uint8_t actor,const RichonlineStockRequest& request) const {
    const auto before=holding(actor,request.slot);
    if((request.action!=RichonlineStockAction::buy && request.action!=RichonlineStockAction::sell) ||
        request.quantity==0 || request.quantity>32767) throw CodecError("richonline_stock_request_fields_invalid");
    const auto market=quote(request.slot);
    const auto funds=ledger_->snapshot(actor);
    if(!funds.funds.deposit) throw CodecError("richonline_stock_deposit_unknown");
    const bool buy=request.action==RichonlineStockAction::buy;
    // 成交总额先按客户端float乘法取整，不能先逐股四舍五入或改为分单位。
    const float total=market.price*static_cast<float>(request.quantity);
    const bool amount_valid=std::isfinite(total) && static_cast<double>(total)<=maximum;
    const auto amount=amount_valid ? static_cast<std::uint32_t>(total) : 0U;
    const char* reason="accepted";
    if(restricted_) reason="restricted";
    else if(buy && market.change_percent>=rise_limit_) reason="rise_limit";
    else if(!buy && market.change_percent<=fall_limit_) reason="fall_limit";
    else if(!amount_valid) reason="amount_limit";
    else if(buy && market.supply<request.quantity) reason="insufficient_supply";
    else if(!buy && before.quantity<request.quantity) reason="insufficient_holding";
    else if(buy && *funds.funds.deposit<amount) reason="insufficient_deposit";
    else if(!buy && amount>maximum-*funds.funds.deposit) reason="deposit_limit";
    else if(buy && request.quantity>maximum-before.quantity) reason="holding_limit";
    else if(!buy && request.quantity>maximum-market.supply) reason="supply_limit";
    Trade result;result.owner_=this;result.revision_=revision_;result.slot_=request.slot;
    result.reason_=reason;result.accepted_=result.reason_=="accepted";
    result.funds_={actor,funds,funds.funds};result.holding_=before;result.supply_=market.supply;
    if(result.accepted_) {
        available_revision(revision_);
        if(buy) {
            result.holding_.quantity+=request.quantity;result.holding_.cost+=total;
            result.supply_-=request.quantity;*result.funds_.after.deposit-=amount;
        } else {
            result.holding_.quantity-=request.quantity;
            // 先检查有足量持股，避免客户端卖出算法中总成本/0的路径。
            result.holding_.cost=(before.cost/static_cast<float>(before.quantity))*static_cast<float>(result.holding_.quantity);
            result.supply_+=request.quantity;*result.funds_.after.deposit+=amount;
        }
        if(!std::isfinite(result.holding_.cost) || result.holding_.cost<0)
            throw CodecError("richonline_stock_cost_invalid");
        append_le(result.response_,buy ? 0x4204 : 0x4205,2);append_le(result.response_,game_,2);
        append_le(result.response_,actor,2);append_le(result.response_,request.slot,2);
        append_le(result.response_,request.quantity,2);append_le(result.response_,0,2);
        append_le(result.response_,std::bit_cast<std::uint32_t>(market.price),4);
        append_le(result.response_,*result.funds_.after.deposit,4);
    }
    if(script_) {
        const auto plan=script_->call("stock.trade",{{"game_id",game_},{"actor",actor},{"slot",request.slot},
            {"quantity",request.quantity},{"buy",buy},{"price",market.price},{"change",market.change_percent},
            {"rise_limit",rise_limit_},{"fall_limit",fall_limit_},{"restricted",restricted_},
            {"amount_valid",amount_valid},{"amount",amount},{"supply",market.supply},
            {"holding",before.quantity},{"deposit",*funds.funds.deposit}});
        const LuaValue expected{{"accepted",result.accepted_},{"reason",result.reason_},
            {"deposit",*result.funds_.after.deposit},{"message",lua_bytes(View(result.response_))}};
        if(plan!=expected) throw CodecError("lua_stock_trade_invalid");
    }
    return result;
}
bool RichonlineStockMarket::commit(const Trade& plan) {
    if(plan.owner_!=this || !plan.accepted_ || plan.revision_!=revision_) return false;
    available_revision(revision_);
    const std::array updates{plan.funds_};
    return ledger_->commit_asset_exchange(updates,[&] {
        // 全部可能失败的计算、Lua和资金校验已完成；回调只写标量，不分配或回调账本。
        holdings_[plan.funds_.actor][plan.slot_]=plan.holding_;
        quotes_[plan.slot_].supply=plan.supply_;++revision_;
        return true;
    });
}
}
