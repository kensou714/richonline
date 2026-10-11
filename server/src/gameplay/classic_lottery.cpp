#include "richonline_classic_lottery.hpp"
#include "richonline_classic_news.hpp"
#include "lua_server.hpp"
#include "lua_wire.hpp"

#include <algorithm>
#include <bit>
#include <limits>

namespace richnet {
namespace {
constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
void validate_number(std::int8_t number) {
    if(number!=-2 && number!=-1 && (number<1 || number>32)) throw CodecError("richonline_lottery_number_invalid");
}
Bytes purchase_reply(std::uint16_t game,std::int8_t number) {
    Bytes packet;append_le(packet,0x402b,2);append_le(packet,game,2);
    packet.push_back(static_cast<std::uint8_t>(number));return packet;
}
}
RichonlineLotteryRequest decode_richonline_lottery_request(View request) {
    if(request.size()!=6 || read_le(request.first(2))!=0x29) throw CodecError("richonline_lottery_request_invalid");
    const auto number=std::bit_cast<std::int8_t>(request[4]);validate_number(number);
    return {static_cast<std::uint16_t>(read_le(request.subspan(2,2))),number,request[5]};
}
RichonlineClassicLottery::RichonlineClassicLottery(std::uint16_t game,std::shared_ptr<RichonlineGameLedger> ledger,
    Now now,std::chrono::milliseconds timeout,RichonlineRouteChooser random,
    std::array<std::uint8_t,2> draw_opaque,std::shared_ptr<LuaServer> script)
    :game_(game),ledger_(std::move(ledger)),now_(std::move(now)),timeout_(timeout),random_(std::move(random)),
     draw_opaque_(draw_opaque),script_(std::move(script)) {
    if(!ledger_ || ledger_->actor_count()<2 || ledger_->actor_count()>4 || !now_ || !random_ ||
        timeout_.count()<=0 || timeout_>std::chrono::minutes{5}) throw CodecError("richonline_lottery_policy_invalid");
    owners_.fill(-1);
}
bool RichonlineClassicLottery::has_numbers() const noexcept {
    return std::ranges::any_of(owners_,[](auto owner){return owner!=-1;});
}
bool RichonlineClassicLottery::can_buy(std::uint8_t actor) const {
    // 原UI门严格现金>1000；存款不计入开启选号的门槛。
    return ledger_->snapshot(actor).funds.cash>1000 && std::ranges::find(owners_,-1)!=owners_.end();
}
void RichonlineClassicLottery::begin(const RichonlineLotteryEntry& entry) {
    if(pending_ || entry.game_id!=game_ || !entry.sequence || entry.actor>=ledger_->actor_count() ||
        entry.position<0 || !can_buy(entry.actor)) throw CodecError("richonline_lottery_entry_invalid");
    pending_=Pending{entry,now_()+timeout_};
}
void RichonlineClassicLottery::validate_pending(const RichonlineLotteryEntry& current) const {
    if(!pending_ || pending_->entry!=current) throw CodecError("richonline_lottery_pending_stale");
}
RichonlineLotteryPurchase RichonlineClassicLottery::handle(std::uint8_t sender,View request,
    const RichonlineLotteryEntry& current,std::uint32_t& jackpot) {
    validate_pending(current);
    const auto choice=decode_richonline_lottery_request(request);
    if(sender!=current.actor || choice.calendar!=current.calendar) throw CodecError("richonline_lottery_sender_calendar_invalid");
    // 自动动作会在客户端把-2替换成最高空号，仅无空号时原样送出-2。
    if(choice.number==-2 && std::ranges::find(owners_,-1)!=owners_.end())
        throw CodecError("richonline_lottery_auto_choice_unresolved");
    return finish(choice.number,now_()>=pending_->deadline,jackpot);
}
std::optional<RichonlineLotteryPurchase> RichonlineClassicLottery::poll(
    const RichonlineLotteryEntry& current,std::uint32_t& jackpot) {
    validate_pending(current);
    if(now_()<pending_->deadline) return {};
    return finish(-1,true,jackpot);
}
RichonlineLotteryPurchase RichonlineClassicLottery::finish(std::int8_t requested,bool timed_out,std::uint32_t& jackpot) {
    validate_number(requested);
    const auto entry=pending_->entry;
    const auto before=ledger_->snapshot(entry.actor);
    const auto owners=owners_;const auto pool=jackpot;
    auto choice=timed_out || requested<1 ? std::int8_t{-1} : requested;
    if(choice!=-1 && (before.funds.cash<=1000 || owners_[static_cast<std::size_t>(choice-1)]!=-1)) choice=-1;
    auto after=before.funds;
    if(choice!=-1) {
        if(pool>maximum-1000 || after.cash>maximum) throw CodecError("richonline_lottery_funds_overflow");
        after.cash-=1000;
    }
    auto packet=purchase_reply(game_,choice);
    if(script_) {
        const auto plan=script_->call("lottery.purchase",{{"game_id",game_},{"requested",requested},
            {"timed_out",timed_out},{"cash",before.funds.cash},
            {"available",requested>=1 && owners[static_cast<std::size_t>(requested-1)]==-1}});
        const LuaValue expected{{"number",choice},{"fee",choice==-1 ? 0 : 1000},{"message",lua_bytes(View(packet))}};
        if(plan!=expected || !plan.at("number").is_number_integer() || !plan.at("fee").is_number_integer())
            throw CodecError("lua_lottery_purchase_invalid");
    }
    RichonlineLotteryPurchase result{std::move(packet),entry,choice,timed_out};
    const std::array updates{RichonlineGameFundsUpdate{entry.actor,before,after}};
    if(!ledger_->commit_batch(updates,[&]() noexcept {
        if(owners_!=owners || jackpot!=pool) return false;
        if(choice!=-1) {owners_[static_cast<std::size_t>(choice-1)]=static_cast<std::int8_t>(entry.actor);jackpot=pool+1000;}
        return true;
    })) throw CodecError("richonline_lottery_purchase_stale");
    pending_.reset();return result;
}
std::optional<RichonlineLotteryDraw> RichonlineClassicLottery::draw(std::uint64_t scan_id,
    std::span<const std::uint8_t> active,std::uint32_t& jackpot) {
    if(!scan_id || scan_id<last_draw_ || pending_ || active.size()!=ledger_->actor_count() || jackpot>maximum)
        throw CodecError("richonline_lottery_draw_context_invalid");
    if(scan_id==last_draw_) return {};
    const auto owners=owners_;const auto pool=jackpot;
    for(const auto owner:owners) if(owner!=-1 && (owner<0 || static_cast<std::size_t>(owner)>=active.size() || !active[static_cast<std::size_t>(owner)]))
        throw CodecError("richonline_lottery_retired_owner");
    if(!has_numbers()) {last_draw_=scan_id;return {};}
    // 原服抽奖分布未知，宿主提供随机源；本项目策略在全部32号码上均匀抽取，允许无人中奖。
    const auto index=random_(32);
    if(index>=32) throw CodecError("richonline_lottery_random_invalid");
    const auto winner=owners[index];const auto number=static_cast<std::uint8_t>(index+1);
    std::vector<RichonlineGameFundsUpdate> updates;
    if(winner!=-1) {
        const auto before=ledger_->snapshot(static_cast<std::uint8_t>(winner));auto after=before.funds;
        if(after.cash>maximum-pool) throw CodecError("richonline_lottery_prize_overflow");
        after.cash+=pool;updates.push_back({static_cast<std::uint8_t>(winner),before,after});
    }
    Bytes packet;append_le(packet,0x402c,2);append_le(packet,game_,2);
    packet.push_back(number);packet.push_back(static_cast<std::uint8_t>(winner));
    packet.insert(packet.end(),draw_opaque_.begin(),draw_opaque_.end());append_le(packet,pool,4);
    if(script_) {
        const auto plan=script_->call("lottery.draw",{{"number",number},{"owners",owners},{"jackpot",pool}});
        const LuaValue expected{{"number",number},{"winner",winner},{"prize",pool},
            {"next_jackpot",winner==-1 ? pool : richonline_classic_initial_news_fines},{"reset",winner!=-1}};
        if(plan!=expected) throw CodecError("lua_lottery_draw_invalid");
        for(const auto* field:{"number","winner","prize","next_jackpot"})
            if(!plan.at(field).is_number_integer()) throw CodecError("lua_lottery_draw_invalid");
    }
    RichonlineLotteryDraw result{std::move(packet),number,winner,pool};
    const auto commit=[&]() noexcept {
        if(owners_!=owners || jackpot!=pool) return false;
        if(winner!=-1) {owners_.fill(-1);jackpot=richonline_classic_initial_news_fines;}
        last_draw_=scan_id;return true;
    };
    // 无人中奖没有资金写入，账本禁止空批次；同一对局锁内只提交去重序号。
    if(!(updates.empty() ? commit() : ledger_->commit_batch(updates,commit)))
        throw CodecError("richonline_lottery_draw_stale");
    return result;
}
void RichonlineClassicLottery::retire(std::uint8_t actor) noexcept {
    for(auto& owner:owners_) if(owner==actor) owner=-1;
    if(pending_ && pending_->entry.actor==actor) pending_.reset();
}
}
