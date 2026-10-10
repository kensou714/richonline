#include "richonline_boss_shop.hpp"
#include "richonline_boss_landing.hpp"
#include <algorithm>
#include <bit>
#include <limits>
#include <string_view>

namespace richnet {
RichonlineBossShop::RichonlineBossShop(const std::filesystem::path& root,RichonlineBossCards& cards,
    std::uint16_t game_id,Now now,std::array<std::uint8_t,2> stock_opaque,RichonlineShopCatalog::Choose choose)
    : cards_(cards),game_id_(game_id),now_(std::move(now)),stock_opaque_(stock_opaque),
      catalog_(RichonlineShopCatalog::load(root,cards.map_name())),choose_(std::move(choose)) {
    if (!now_) throw CodecError("richonline_shop_clock_required");
    configure_refresh(load_richonline_gold_charges(root/"Data"/"GoldCharge.kpd"),{});
    // Live session assembly supplies its shared RNG; this fallback keeps existing
    // standalone deterministic callers independent of a second random source.
    if (!choose_) choose_=[](std::size_t) { return std::size_t{0}; };
}
RichonlineBossShop::RichonlineBossShop(const std::filesystem::path& root,RichonlineBossCards& cards,
    std::uint16_t game_id,std::shared_ptr<RichonlineGameLedger> ledger,Now now,
    std::array<std::uint8_t,2> stock_opaque,RichonlineShopCatalog::Choose choose)
    : RichonlineBossShop(root,cards,game_id,std::move(now),stock_opaque,std::move(choose)) {
    if (!ledger) throw CodecError("richonline_shop_ledger_required");
    ledger_=std::move(ledger);
}
void RichonlineBossShop::configure_refresh(const RichonlineGoldCharges& values,ChargeReserve charge) {
    if (active()) throw CodecError("richonline_shop_already_open");
    const auto found=values.values.find(4);
    if (found==values.values.end()) refresh_cost_.reset();
    else {
        if (found->second<0) throw CodecError("richonline_shop_refresh_cost_invalid");
        refresh_cost_=static_cast<std::uint32_t>(found->second);
    }
    charge_reserve_=std::move(charge);
}
Bytes RichonlineBossShop::response(std::uint16_t opcode,std::int8_t index) const {
    Bytes bytes; append_le(bytes,opcode,2); append_le(bytes,game_id_,2);
    bytes.push_back(static_cast<std::uint8_t>(index)); return bytes;
}
Bytes RichonlineBossShop::stock(const RichonlineShopStock& offers,bool refreshed) const {
    Bytes bytes; append_le(bytes,0x4030,2); append_le(bytes,game_id_,2);
    for (const auto& offer:offers) {
        append_le(bytes,static_cast<std::uint16_t>(offer.card_id),2);
        append_le(bytes,static_cast<std::uint16_t>(offer.count),2);
        bytes.insert(bytes.end(),stock_opaque_.begin(),stock_opaque_.end());
    }
    bytes.push_back(static_cast<std::uint8_t>(refreshed)); return bytes;
}
bool RichonlineBossShop::validate_landing(const RichonlineLandingContext& context) const {
    if (context.actor_slot!=0 || context.synthetic_actor || context.game_mode!=3 || context.static_type!=10 ||
        context.position<0 || context.property_ref!=-1 || (context.occupied_by_other_actor && !context.collision_resolved) ||
        context.road_degree==0 || context.road_degree>4) return false;
    if (active()) throw CodecError("richonline_shop_already_open");
    if (!richonline_landing_controlled(context.actor_status) &&
        points()>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw CodecError("richonline_shop_points_invalid");
    return true;
}
std::optional<RichonlineLandingResult> RichonlineBossShop::land(const RichonlineLandingContext& context,std::uint32_t points) {
    if (!validate_landing(context)) return {};
    if(auto controlled=resolve_richonline_controlled_static_landing(game_id_,context)) return controlled;
    if (ledger_ && points!=ledger_->snapshot(0).funds.tickets) throw CodecError("richonline_shop_stale_open_balance");
    if (points>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw CodecError("richonline_shop_points_invalid");
    Bytes stop; append_le(stop,0x4013,2); append_le(stop,game_id_,2);
    append_le(stop,static_cast<std::uint16_t>(context.position),2);
    const auto next=catalog_.select(choose_);
    RichonlineLandingResult result{{std::move(stop),stock(next,false)},RichonlineLandingProgress::await_event,0x30};
    points_=points; offers_=next; refreshes_=0;
    deadline_=now_()+std::chrono::seconds{10};
    last_decision_="opened";
    return result;
}
std::optional<RichonlineLandingResult> RichonlineBossShop::land(const RichonlineLandingContext& context) {
    if (!ledger_) throw CodecError("richonline_shop_ledger_required");
    return land(context,ledger_->snapshot(0).funds.tickets);
}
RichonlineLandingResult RichonlineBossShop::close(const char* reason) {
    if (!active()) return {{},RichonlineLandingProgress::complete};
    RichonlineLandingResult result{{response(0x4031,-1)},RichonlineLandingProgress::complete};
    deadline_.reset(); last_decision_=reason; return result;
}
std::optional<RichonlineLandingResult> RichonlineBossShop::poll() {
    if (!active() || now_()<*deadline_) return {};
    return close("deadline_expired");
}
RichonlineLandingResult RichonlineBossShop::handle(View request) {
    if (request.size()<2) throw CodecError("richonline_shop_request_length_invalid");
    const auto opcode=read_le(request.first(2));
    if (opcode!=0x30 && opcode!=0x31 && opcode!=0x35) throw CodecError("richonline_shop_opcode_unsupported");
    if (request.size()!=(opcode==0x35 ? 4U : 6U)) throw CodecError("richonline_shop_request_length_invalid");
    if (opcode==0x30 && std::bit_cast<std::int8_t>(request[4])==-1) return close("client_exit");
    if (!active()) throw CodecError("richonline_shop_not_open");
    if (now_()>=*deadline_) return close("deadline_expired");
    if (opcode==0x35) {
        if (!charge_reserve_ || !refresh_cost_) return close("refresh_unavailable");
        if (refreshes_>=5) return close("refresh_limit");
        const auto next=catalog_.select(choose_);
        RichonlineLandingResult result{{stock(next,true)},RichonlineLandingProgress::await_event,0x30};
        if (!charge_reserve_(*refresh_cost_)) return close("refresh_insufficient_reserve");
        offers_=next; ++refreshes_; last_decision_="refreshed"; return result;
    }
    const auto index=std::bit_cast<std::int8_t>(request[4]);
    const auto expected=ledger_ ? std::optional{ledger_->snapshot(0)} : std::nullopt;
    const auto current_points=expected ? expected->funds.tickets : points_;
    const auto commit_points=[&](std::int64_t delta) {
        if (!ledger_) { points_=static_cast<std::uint32_t>(static_cast<std::int64_t>(current_points)+delta); return true; }
        try { ledger_->adjust(0,*expected,{0,0,delta,0}); return true; }
        catch (const CodecError& error) {
            if (std::string_view(error.what())=="richonline_game_ledger_conflict") return false;
            throw;
        }
    };
    if (opcode==0x30) {
        if (index<0 || index>=12) return close("buy_index_invalid");
        auto& offer=offers_[static_cast<std::size_t>(index)];
        if (offer.card_id==-1) return close("offer_empty");
        const auto price=catalog_.price(offer.card_id);
        if (current_points<price) return close("insufficient_tickets");
        if (std::none_of(cards_.inventory().begin(),cards_.inventory().end(),
            [](const auto& slot) { return slot.card_id==-1; })) return close("inventory_full");
        const auto next=cards_.prepare_add(offer.card_id,offer.count);
        RichonlineLandingResult result{{response(0x4031,index)},RichonlineLandingProgress::await_event,0x30};
        if (!commit_points(-static_cast<std::int64_t>(price))) return close("ledger_conflict");
        cards_.commit_inventory(next); offer={};
        last_decision_="bought";
        return result;
    }
    if (index<0 || index>=8) return close("sell_index_invalid");
    auto next=cards_.inventory();
    const auto slot=static_cast<std::size_t>(index);
    if (next[slot].card_id==-1 || next[slot].count<1) return close("inventory_slot_empty");
    const auto refund=catalog_.price(next[slot].card_id)/2;
    if (refund>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())-current_points) return close("tickets_overflow");
    next[slot]={};
    RichonlineLandingResult result{{response(0x4032,index)},RichonlineLandingProgress::await_event,0x30};
    if (!commit_points(refund)) return close("ledger_conflict");
    cards_.commit_inventory(next);
    last_decision_="sold";
    return result;
}
}
