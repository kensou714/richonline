#include "richonline_game_payment.hpp"
#include "original_options.hpp"
#include <algorithm>
#include <charconv>
#include <cmath>
#include <limits>

namespace richnet {
namespace {
std::string_view trim(std::string_view text) {
    const auto first=text.find_first_not_of(" \t\r");
    return first==text.npos ? std::string_view{} : text.substr(first,text.find_last_not_of(" \t\r")-first+1);
}
std::int32_t integer(std::string_view text) {
    std::int32_t result{};const auto parsed=std::from_chars(text.data(),text.data()+text.size(),result);
    if(text.empty() || parsed.ec!=std::errc{} || parsed.ptr!=text.data()+text.size() || result<0)
        throw CodecError("richonline_gold_charge_integer_invalid");
    return result;
}
}
std::int32_t RichonlineGoldCharges::require(std::int32_t index) const {
    const auto found=values.find(index);
    if(found==values.end())throw CodecError("richonline_gold_charge_missing");
    return found->second;
}
RichonlineGoldCharges parse_richonline_gold_charges(View decoded) {
    if(decoded.empty() || decoded.size()>65536)throw CodecError("richonline_gold_charge_resource_size");
    std::string_view text(reinterpret_cast<const char*>(decoded.data()),decoded.size());
    if(text.find('\0')!=text.npos)throw CodecError("richonline_gold_charge_nul");
    RichonlineGoldCharges result;std::optional<std::int32_t> index,charge;bool section=false;
    const auto flush=[&]{
        if(!section)return;
        if(!index || !charge)throw CodecError("richonline_gold_charge_field_missing");
        if(!result.values.emplace(*index,*charge).second)throw CodecError("richonline_gold_charge_duplicate");
        index.reset();charge.reset();
    };
    while(!text.empty()) {
        const auto end=text.find('\n');const auto line=trim(text.substr(0,end));
        text=end==text.npos ? std::string_view{} : text.substr(end+1);
        if(line.empty() || line.starts_with("//"))continue;
        if(line=="[ITEM]"){flush();section=true;continue;}
        const auto eq=line.find('=');
        if(!section || eq==line.npos)throw CodecError("richonline_gold_charge_line_invalid");
        const auto name=trim(line.substr(0,eq));const auto value=integer(trim(line.substr(eq+1)));
        if(name=="indx" && !index)index=value;
        else if(name=="charge" && !charge)charge=value;
        else throw CodecError("richonline_gold_charge_field_invalid");
    }
    flush();if(result.values.empty())throw CodecError("richonline_gold_charge_empty");return result;
}
RichonlineGoldCharges load_richonline_gold_charges(const std::filesystem::path& path) {
    return parse_richonline_gold_charges(load_original_kpd(path,65536));
}
std::uint32_t richonline_initial_reserve(double gold,double fee,const RichonlineGoldCharges& charges) {
    if(!std::isfinite(gold) || !std::isfinite(fee) || gold<0 || fee<0)
        throw CodecError("richonline_payment_initial_state_invalid");
    const auto initial=std::trunc(gold-fee);
    if(initial<std::numeric_limits<std::int32_t>::min() || initial>std::numeric_limits<std::int32_t>::max())
        throw CodecError("richonline_payment_initial_reserve_range");
    const auto floor=charges.require(5);
    if(floor<0)throw CodecError("richonline_payment_charge_invalid");
    return static_cast<std::uint32_t>(std::max(static_cast<std::int32_t>(initial),floor));
}
RichonlineGamePayment::RichonlineGamePayment(std::shared_ptr<RichonlineGameLedger> ledger,std::uint8_t actor,RichonlineGoldCharges charges,Debit debit)
    :ledger_(std::move(ledger)),actor_(actor),charges_(std::move(charges)),debit_(std::move(debit)) {
    if(!ledger_ || !debit_ || charges_.require(3)<=0 || charges_.require(4)<=0)
        throw CodecError("richonline_payment_initial_state_invalid");
    (void)reserve();
}
std::uint32_t RichonlineGamePayment::reserve() const {
    const auto value=ledger_->snapshot(actor_).funds.reserve;
    if(!value)throw CodecError("richonline_payment_reserve_unknown");
    return *value;
}
RichonlinePaymentResult RichonlineGamePayment::paid_die(const std::string& operation,std::uint8_t die,RichonlinePaidDiceEquipment equipment) {
    const auto price=quote_paid_die(die,equipment);
    return pay(operation,"paid controlled die face="+std::to_string(die),price);
}
std::int32_t RichonlineGamePayment::quote_paid_die(std::uint8_t die,RichonlinePaidDiceEquipment equipment) const {
    if(die<1 || die>6)throw CodecError("richonline_payment_action_invalid");
    const auto price=charges_.require(3);
    return equipment.equipped_die?0:equipment.vehicle_discount?price/2:price;
}
std::int32_t RichonlineGamePayment::quote_random_dice(std::uint8_t count,RichonlinePaidDiceEquipment equipment) const {
    if(count<1 || count>3) throw CodecError("richonline_payment_action_invalid");
    std::int32_t price=0;
    switch(equipment.dice_vehicle) {
    case RichonlineDiceVehicle::walking:
        if(count>1) price=charges_.require(count==2?0:1);
        break;
    case RichonlineDiceVehicle::motorcycle:
        if(count==3) price=charges_.require(2);
        break;
    case RichonlineDiceVehicle::car:break;
    default:throw CodecError("richonline_payment_vehicle_invalid");
    }
    if(price<0) throw CodecError("richonline_payment_charge_invalid");
    return price;
}
RichonlinePaymentResult RichonlineGamePayment::random_dice(const std::string& operation,std::uint8_t count,
    RichonlinePaidDiceEquipment equipment) {
    return pay(operation,"random dice count="+std::to_string(count),quote_random_dice(count,equipment));
}
RichonlinePaymentResult RichonlineGamePayment::shop_refresh(const std::string& operation) {
    return pay(operation,"shop refresh",charges_.require(4));
}
RichonlinePaymentResult RichonlineGamePayment::pay(const std::string& operation,std::string reason,std::int32_t cost) {
    const std::lock_guard lock(mutex_);
    if(operation.empty() || operation.size()>256 || operation.find('\0')!=operation.npos)
        throw CodecError("richonline_payment_action_invalid");
    const auto prior=completed_.find(operation);
    if(prior!=completed_.end()) {
        if(prior->second.reason!=reason || prior->second.cost!=cost)throw CodecError("richonline_payment_action_conflict");
        auto result=prior->second.result;
        if(result.status==RichonlinePaymentStatus::committed)result.status=RichonlinePaymentStatus::duplicate;
        return result;
    }
    const auto before=ledger_->snapshot(actor_);
    if(!before.funds.reserve)throw CodecError("richonline_payment_reserve_unknown");
    const auto available=*before.funds.reserve;
    if(available<static_cast<std::uint32_t>(cost))return {RichonlinePaymentStatus::insufficient_reserve,0,available};
    // Allocate the result cache and DB request before any persistent mutation.
    const GameGoldCharge request{static_cast<double>(cost),operation,reason};
    auto [entry,inserted]=completed_.emplace(operation,Completed{std::move(reason),cost,{RichonlinePaymentStatus::recovery_required,0,available}});
    (void)inserted;
    try {
        const auto after=ledger_->consume_reserve(actor_,static_cast<std::uint32_t>(cost),[&]{
            if(cost==0)return true;
            const auto result=debit_(request);
            if(result.status!=GameChargeStatus::success){entry->second.result.status=RichonlinePaymentStatus::account_refused;return false;}
            // Restart replay needs gameplay recovery, not a second charge/move.
            return !result.replayed;
        });
        if(after)entry->second.result={RichonlinePaymentStatus::committed,cost,*after->funds.reserve};
    }catch(const CodecError& error){
        if(std::string_view(error.what())=="richonline_game_ledger_insufficient") {
            entry->second.result={RichonlinePaymentStatus::insufficient_reserve,0,reserve()};
            return entry->second.result;
        }
        completed_.erase(entry);throw;
    }catch(...){completed_.erase(entry);throw;}
    return entry->second.result;
}
}
