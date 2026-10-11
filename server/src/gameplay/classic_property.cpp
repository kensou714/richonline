#include "richonline_classic_property.hpp"
#include "richonline_property_wire.hpp"
#include "lua_wire.hpp"

#include <limits>
#include <bit>
#include <utility>

namespace richnet {
namespace {
constexpr auto maximum_cash=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
std::uint16_t opcode(RichonlineClassicPropertyChoice choice) {
    switch(choice) {
    case RichonlineClassicPropertyChoice::purchase: return 0x20;
    case RichonlineClassicPropertyChoice::upgrade: return 0x21;
    }
    throw CodecError("richonline_classic_property_choice_invalid");
}
}
RichonlineClassicProperty::RichonlineClassicProperty(std::uint16_t game_id,RichonlineRoadTopology topology,
    const RichonlinePropertyResources& resources,std::shared_ptr<RichonlineGameLedger> ledger,
    Now now,std::chrono::milliseconds timeout,std::shared_ptr<LuaServer> script)
    :game_id_(game_id),topology_(std::move(topology)),ledger_(std::move(ledger)),now_(std::move(now)),
     timeout_(timeout),script_(std::move(script)) {
    if(!ledger_ || ledger_->actor_count()<2 || ledger_->actor_count()>4)
        throw CodecError("richonline_classic_property_ledger_invalid");
    // 超时时长为调用者显式配置的服务端恢复策略，不冒充原服务器超时证据。
    if(!now_ || timeout_.count()<=0 || timeout_>std::chrono::minutes{10})
        throw CodecError("richonline_classic_property_clock_invalid");
    if(resources.width!=topology_.width() || resources.height!=topology_.height())
        throw CodecError("richonline_classic_property_map_mismatch");
    for(const auto& property:resources.properties) {
        if(property.id<0 || static_cast<std::size_t>(property.id)>=topology_.cells().size() ||
            (property.sprite_type!=11 && property.sprite_type!=12) || property.kind< -1 ||
            property.kind>10 || property.level>5 || property.owner || property.price>maximum_cash)
            throw CodecError("richonline_classic_property_resource_invalid");
        for(const auto road:property.road_tiles) {
            const auto& cell=topology_.cell(road);
            if(!cell.walkable || cell.property_ref!=property.id)
                throw CodecError("richonline_classic_property_reference_mismatch");
        }
        if(!properties_.emplace(property.id,RichonlineClassicPropertyState{property.id,property.sprite_type,
            property.kind,property.level,property.owner,property.price}).second)
            throw CodecError("richonline_classic_property_duplicate");
        districts_.emplace(property.id,property.district);
    }
    for(const auto& cell:topology_.cells())
        if(cell.walkable && cell.property_ref>=0 && !properties_.contains(cell.property_ref))
            throw CodecError("richonline_classic_property_reference_missing");
}
RichonlineClassicPropertyState RichonlineClassicProperty::snapshot(std::int16_t property) const {
    const auto found=properties_.find(property);
    if(found==properties_.end()) throw CodecError("richonline_classic_property_unknown");
    return found->second;
}
std::vector<std::uint64_t> RichonlineClassicProperty::asset_values(
    const std::function<std::uint64_t(const RichonlineClassicPropertyState&)>& valuation) const {
    if(pending_ || !valuation) throw CodecError("richonline_classic_property_valuation_unavailable");
    std::vector<std::uint64_t> totals(ledger_->actor_count());
    constexpr auto maximum=static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    for(const auto& [id,property]:properties_) {
        if(!property.owner) continue;
        auto& total=totals.at(*property.owner);
        const auto value=valuation(property);
        if(value>maximum-total) throw CodecError("richonline_classic_property_asset_overflow");
        total+=value;
    }
    return totals;
}
std::int32_t RichonlineClassicProperty::rent_quote(std::int16_t property,std::uint32_t monetary_scale) const {
    const auto target=snapshot(property);
    if(!target.owner || (target.kind!=0 && target.kind!=1))
        throw CodecError("richonline_classic_rent_property_invalid");
    constexpr std::array<std::uint32_t,6> coefficients{500,1000,2500,5000,8000,12500};
    std::uint32_t total=0;
    auto items=LuaValue::array();
    for(const auto& [id,item]:properties_) {
        if(item.sprite_type!=11 || item.kind!=target.kind || item.owner!=target.owner ||
            (target.kind==0 && districts_.at(id)!=districts_.at(property))) continue;
        if(item.level>=coefficients.size()) throw CodecError("richonline_classic_rent_level_invalid");
        // unsigned乘法保留低32位；转为signed后逐块除1000，不能先累加再整除。
        const auto part=target.kind==0 ? static_cast<std::uint32_t>(
            std::bit_cast<std::int32_t>(item.price*monetary_scale*coefficients[item.level])/1000) :
            monetary_scale*4000U;
        total+=part;
        items.push_back({{"price",item.price},{"level",item.level}});
    }
    const auto quote=std::bit_cast<std::int32_t>(total);
    if(script_) {
        const auto plan=script_->call("property.classic_rent_quote",{{"kind",target.kind},
            {"scale",monetary_scale},{"items",std::move(items)}});
        if(!plan.is_number_integer() || plan!=LuaValue(quote))
            throw CodecError("lua_classic_rent_quote_invalid");
    }
    return quote;
}
void RichonlineClassicProperty::validate_entry(const RichonlineClassicPropertyEntry& entry) const {
    if(entry.game_id!=game_id_ || entry.actor>=ledger_->actor_count() || !entry.status.possession)
        throw CodecError("richonline_classic_property_actor_invalid");
    const auto& cell=topology_.cell(entry.position);
    if(!cell.walkable || cell.property_ref!=entry.property || !properties_.contains(entry.property))
        throw CodecError("richonline_classic_property_landing_mismatch");
}
RichonlineClassicProperty::Retirement RichonlineClassicProperty::prepare_retirement(std::uint8_t actor) const {
    if(actor>=ledger_->actor_count() || pending_)
        throw CodecError("richonline_classic_property_retirement_invalid");
    Retirement result;result.owner_=this;result.actor_=actor;result.before_=properties_;
    return result;
}
bool RichonlineClassicProperty::matches(const Retirement& plan) const noexcept {
    return plan.owner_==this && !pending_ && properties_==plan.before_;
}
bool RichonlineClassicProperty::commit_retirement(const Retirement& plan) noexcept {
    if(!matches(plan)) return false;
    for(auto& [id,property]:properties_) {
        static_cast<void>(id);
        if(property.owner==plan.actor_) property.owner.reset();
    }
    return true;
}
RichonlineClassicProperty::Disaster RichonlineClassicProperty::prepare_disaster(
    std::int16_t property,std::uint8_t levels) const {
    if(pending_ || (levels!=1 && levels!=5))
        throw CodecError("richonline_classic_disaster_context_invalid");
    Disaster plan;plan.owner_=this;plan.levels_=levels;
    plan.before_=plan.after_=snapshot(property);
    auto& after=plan.after_;
    if(after.level && after.kind!=8 && after.kind!=9 && after.kind!=10) {
        // 本类已限制等级0..5，因此BYTE减法后signed<=0与这里的归零等价。
        after.level=after.level>levels ? static_cast<std::uint8_t>(after.level-levels) : 0;
        if(!after.level) after.kind=after.sprite_type==11 ? 0 : -1;
        // 住宅kind1归零的7E3E60/7E3C00先清后恢复原owner，净结果不转移产权。
    }
    return plan;
}
bool RichonlineClassicProperty::commit_disaster(const Disaster& plan) noexcept {
    if(plan.owner_!=this || pending_) return false;
    const auto found=properties_.find(plan.before_.id);
    if(found==properties_.end() || found->second!=plan.before_) return false;
    found->second=plan.after_;return true;
}
std::uint16_t RichonlineClassicProperty::begin(RichonlineClassicPropertyChoice choice,
    const RichonlineClassicPropertyEntry& entry) {
    if(pending_) throw CodecError("richonline_classic_property_already_pending");
    const auto request_opcode=opcode(choice);
    validate_entry(entry);
    const auto property=snapshot(entry.property);
    if(*entry.status.possession==7 || entry.status.sleepwalking || entry.status.frozen)
        throw CodecError("richonline_classic_property_controlled");
    if(property.kind==8 || property.kind==9 || property.kind==10)
        throw CodecError("richonline_classic_property_special_kind_unsupported");
    std::uint32_t cost=property.price;
    if(choice==RichonlineClassicPropertyChoice::purchase) {
        if(property.owner) throw CodecError("richonline_classic_property_already_owned");
    } else {
        if(property.owner!=entry.actor || property.level>=5 || property.kind==1 || entry.sealed)
            throw CodecError("richonline_classic_property_upgrade_ineligible");
        // sprite12空地确认会转入UI13/0023，而不是扣费增级；未接该选择前明确拒绝。
        if(property.sprite_type!=11 && (property.kind<2 || property.kind>6))
            throw CodecError("richonline_classic_property_building_choice_required");
        cost=property.sprite_type==11 ? 500 : 1500;
    }
    if(entry.land_equipment>0) cost/=2;
    const auto funds=ledger_->snapshot(entry.actor);
    if(funds.funds.cash>maximum_cash || funds.funds.cash<=cost)
        throw CodecError("richonline_classic_property_cash_ineligible");
    pending_=Pending{choice,entry,property,cost,now_()+timeout_};
    return request_opcode;
}
void RichonlineClassicProperty::validate_pending(const RichonlineClassicPropertyEntry& current) const {
    if(!pending_) throw CodecError("richonline_classic_property_not_pending");
    validate_entry(current);
    if(current!=pending_->entry || snapshot(current.property)!=pending_->property)
        throw CodecError("richonline_classic_property_pending_stale");
}
RichonlineClassicPropertyResult RichonlineClassicProperty::finish(bool requested,bool timed_out) {
    const auto pending=*pending_;
    const auto before_funds=ledger_->snapshot(pending.entry.actor);
    if(before_funds.funds.cash>maximum_cash)
        throw CodecError("richonline_classic_property_cash_invalid");
    bool accepted=false;
    auto outcome=RichonlineClassicPropertyOutcome::declined;
    const char* reason="declined";
    if(timed_out) { outcome=RichonlineClassicPropertyOutcome::timed_out; reason="timed_out"; }
    else if(requested) {
        if(before_funds.funds.cash<=pending.cost) {
            outcome=RichonlineClassicPropertyOutcome::insufficient_funds;reason="insufficient_funds";
        } else { accepted=true;outcome=RichonlineClassicPropertyOutcome::accepted;reason="accepted"; }
    }
    const auto charged=accepted ? pending.cost : 0U;
    auto after=pending.property;
    // 原版普通模式状态2只扣费，不移交产权/增级；不能在这里自动退款。
    if(accepted && *pending.entry.status.possession!=2) {
        if(pending.choice==RichonlineClassicPropertyChoice::purchase) after.owner=pending.entry.actor;
        else ++after.level;
    }
    auto message=pending.choice==RichonlineClassicPropertyChoice::purchase ?
        richonline_property_response(game_id_,accepted) : richonline_property_upgrade_response(game_id_,accepted);
    if(script_) {
        const auto plan=script_->call("property.classic_choice",{{"game_id",game_id_},
            {"choice",opcode(pending.choice)},{"requested",requested},{"timed_out",timed_out},
            {"cash",before_funds.funds.cash},{"cost",pending.cost},
            {"actor",pending.entry.actor},{"owner",pending.property.owner ? static_cast<int>(*pending.property.owner) : -1},
            {"level",pending.property.level},{"possession",*pending.entry.status.possession}});
        const LuaValue expected{{"accepted",accepted},{"charged",charged},{"outcome",reason},
            {"owner",after.owner ? static_cast<int>(*after.owner) : -1},{"level",after.level},
            {"message",lua_bytes(View(message))}};
        if(plan!=expected || !plan.at("charged").is_number_integer() ||
            !plan.at("owner").is_number_integer() || !plan.at("level").is_number_integer())
            throw CodecError("lua_classic_property_choice_invalid");
    }
    RichonlineClassicPropertyResult result{std::move(message),pending.entry,pending.property,after,outcome,charged};
    auto after_funds=before_funds.funds;
    after_funds.cash-=charged;
    const std::array updates{RichonlineGameFundsUpdate{pending.entry.actor,before_funds,after_funds}};
    // 响应及Lua计划全部准备好后提交。账本先校验版本，回调只写标量且不反调账本。
    auto& state=properties_.at(pending.entry.property);
    if(!ledger_->commit_batch(updates,[&]() {
        if(state!=pending.property) return false;
        state=after;
        pending_.reset();
        return true;
    })) throw CodecError("richonline_classic_property_commit_stale");
    return result;
}
RichonlineClassicPropertyResult RichonlineClassicProperty::handle(std::uint8_t sender_actor,View request,
    const RichonlineClassicPropertyEntry& current) {
    validate_pending(current);
    if(sender_actor!=pending_->entry.actor) throw CodecError("richonline_classic_property_sender_mismatch");
    std::uint16_t calendar;
    bool accept;
    if(pending_->choice==RichonlineClassicPropertyChoice::purchase) {
        const auto decoded=decode_richonline_property_request(request);
        calendar=decoded.calendar;accept=decoded.accept;
    } else {
        const auto decoded=decode_richonline_property_upgrade_request(request);
        calendar=decoded.calendar;accept=decoded.accept;
    }
    if(calendar!=pending_->entry.calendar) throw CodecError("richonline_classic_property_calendar_mismatch");
    return finish(accept,now_()>=pending_->deadline);
}
std::optional<RichonlineClassicPropertyResult> RichonlineClassicProperty::poll(
    const RichonlineClassicPropertyEntry& current) {
    if(!pending_) return {};
    validate_pending(current);
    if(now_()<pending_->deadline) return {};
    return finish(false,true);
}
}
