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
    Now now,std::chrono::milliseconds timeout,std::shared_ptr<LuaServer> script,
    std::optional<RichonlineClassicBuildingPolicy> buildings)
    :game_id_(game_id),topology_(std::move(topology)),ledger_(std::move(ledger)),now_(std::move(now)),
     timeout_(timeout),script_(std::move(script)),buildings_(std::move(buildings)) {
    if(!ledger_ || ledger_->actor_count()<2 || ledger_->actor_count()>4)
        throw CodecError("richonline_classic_property_ledger_invalid");
    // 超时时长为调用者显式配置的服务端恢复策略，不冒充原服务器超时证据。
    if(!now_ || timeout_.count()<=0 || timeout_>std::chrono::minutes{10})
        throw CodecError("richonline_classic_property_clock_invalid");
    if(buildings_) {
        if(!buildings_->resources || buildings_->cards.size()!=ledger_->actor_count())
            throw CodecError("richonline_classic_building_policy_invalid");
        for(std::size_t actor=0;actor<buildings_->cards.size();++actor) {
            const auto& cards=buildings_->cards[actor];
            if(!cards || cards->game_id()!=game_id_ || cards->actor_slot()!=actor || cards->game_mode()!=0)
                throw CodecError("richonline_classic_building_cards_mismatch");
        }
    }
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
        if(property.kind!=8 && property.kind!=9 && property.kind!=10)
            ordinary_properties_.push_back(property.id);
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
RichonlineClassicProperty::CardChange RichonlineClassicProperty::prepare_card_purchase(
    std::int16_t property,std::uint8_t actor) const {
    if(pending_ || actor>=ledger_->actor_count()) throw CodecError("richonline_classic_property_card_context_invalid");
    CardChange plan;plan.owner_=this;
    plan.before_={snapshot(property)};plan.after_=plan.before_;
    const auto& before=plan.before_[0];
    if(before.owner==actor || before.kind==8 || before.kind==9 || before.kind==10)
        throw CodecError("richonline_classic_purchase_card_target_invalid");
    plan.after_[0].owner=actor;return plan;
}
RichonlineClassicProperty::CardChange RichonlineClassicProperty::prepare_card_swap(
    std::int16_t source,std::int16_t target,bool buildings) const {
    if(pending_ || source==target) throw CodecError("richonline_classic_swap_card_context_invalid");
    CardChange plan;plan.owner_=this;
    plan.before_={snapshot(source),snapshot(target)};plan.after_=plan.before_;
    const auto& a=plan.before_[0];const auto& b=plan.before_[1];
    if(a.sprite_type!=b.sprite_type || a.kind==8 || a.kind==9 || a.kind==10 ||
        b.kind==8 || b.kind==9 || b.kind==10)
        throw CodecError("richonline_classic_swap_card_target_invalid");
    if(buildings) {
        if(!a.level || !b.level) throw CodecError("richonline_classic_swap_card_building_empty");
        std::swap(plan.after_[0].kind,plan.after_[1].kind);
        std::swap(plan.after_[0].level,plan.after_[1].level);
    } else {
        if(a.owner==b.owner) throw CodecError("richonline_classic_swap_card_owner_equal");
        std::swap(plan.after_[0].owner,plan.after_[1].owner);
    }
    return plan;
}
RichonlineClassicProperty::CardChange RichonlineClassicProperty::prepare_card_open_shop(
    std::int16_t property) const {
    if(pending_) throw CodecError("richonline_classic_open_shop_choice_pending");
    CardChange plan;plan.owner_=this;
    plan.before_={snapshot(property)};plan.after_=plan.before_;
    const auto& before=plan.before_[0];
    // 652F40先经7E4440排除保护地产，再要求有产权、sprite11、非零级且非商店。
    // 没有要求属于施放者，也没有查封排除门；不能额外限制为自有或未查封住宅。
    if(!before.owner || before.sprite_type!=11 || !before.level || before.kind==1 ||
        before.kind==8 || before.kind==9 || before.kind==10)
        throw CodecError("richonline_classic_open_shop_target_invalid");
    // 40B3排6074解除、6076转换、6071恢复原产权。694E40同时写kind1和level1，
    // 地价、街区与两个计时不变；小型地产不涉及经典研究所登记。
    plan.after_[0].kind=1;plan.after_[0].level=1;
    return plan;
}
RichonlineClassicProperty::CardChange RichonlineClassicProperty::prepare_card_destruction(
    std::int16_t property,std::uint8_t levels) const {
    // 与新闻使用同一降级算法，但主动卡须有非保护且非零级建筑。
    const auto disaster=prepare_disaster(property,levels);
    const auto& before=disaster.before();
    if(!before.level || before.kind==8 || before.kind==9 || before.kind==10)
        throw CodecError("richonline_classic_destruction_card_target_invalid");
    CardChange plan;plan.owner_=this;
    plan.before_={before};plan.after_={disaster.after()};return plan;
}
RichonlineClassicProperty::CardChange RichonlineClassicProperty::prepare_card_street(
    std::int16_t property,StreetEffect effect) const {
    if(pending_) throw CodecError("richonline_classic_street_choice_pending");
    if(effect!=StreetEffect::seal && effect!=StreetEffect::price_rise)
        throw CodecError("richonline_classic_street_effect_invalid");
    const auto source=snapshot(property);
    if(effect==StreetEffect::price_rise && (source.kind==8 || source.kind==9 || source.kind==10))
        throw CodecError("richonline_classic_price_rise_target_protected");
    const auto district=districts_.at(property);
    CardChange plan;plan.owner_=this;
    for(const auto id:ordinary_properties_) if(districts_.at(id)==district) {
        const auto& state=properties_.at(id);
        plan.before_.push_back(state);auto after=state;
        if(effect==StreetEffect::seal) after.sealed_days=5;
        else after.price_rise_days=5;
        plan.after_.push_back(after);
    }
    return plan;
}
RichonlineClassicProperty::CardChange RichonlineClassicProperty::prepare_card_growth(
    std::int16_t property,std::int8_t levels) const {
    if(pending_ || (levels!=1 && levels!=-1))
        throw CodecError("richonline_classic_growth_context_invalid");
    const auto source=snapshot(property);
    if(source.kind==8 || source.kind==9 || source.kind==10)
        throw CodecError("richonline_classic_growth_target_protected");
    const auto district=districts_.at(property);
    CardChange plan;plan.owner_=this;
    for(const auto id:ordinary_properties_) if(districts_.at(id)==district) {
        const auto& before=properties_.at(id);auto after=before;
        if(levels>0) {
            // 7E3670固定上限5；type11商店不升级，type12空地先变贸易中心kind3。
            if(after.level<5 && !(after.sprite_type==11 && after.kind==1)) {
                if(after.sprite_type==12 && !after.level) after.kind=3;
                ++after.level;
            }
        } else if(after.level) {
            // 7E3840无商店例外；7E4020降至0按地类清建筑，原owner净值不变。
            --after.level;
            if(!after.level) after.kind=after.sprite_type==11 ? 0 : -1;
        }
        plan.before_.push_back(before);plan.after_.push_back(after);
    }
    return plan;
}
RichonlineClassicProperty::CardChange RichonlineClassicProperty::prepare_card_conversion(
    std::int16_t property,std::int8_t kind) const {
    if(pending_ || kind<2 || kind>6)
        throw CodecError("richonline_classic_conversion_context_invalid");
    CardChange plan;plan.owner_=this;
    plan.before_={snapshot(property)};plan.after_=plan.before_;
    const auto& before=plan.before_[0];
    if(before.sprite_type!=12 || !before.level || before.kind==kind ||
        before.kind==8 || before.kind==9 || before.kind==10)
        throw CodecError("richonline_classic_conversion_target_invalid");
    // 681110只写kind；产权、等级、街区计时及研发登记由各自生命周期处理。
    plan.after_[0].kind=kind;
    return plan;
}
bool RichonlineClassicProperty::matches(const CardChange& plan) const noexcept {
    // 特殊建筑脚下也可合法使用查封；同组无普通地产时仍扣卡，变更集合可以为空。
    if(plan.owner_!=this || pending_ || plan.before_.size()!=plan.after_.size()) return false;
    for(const auto& before:plan.before()) {
        const auto found=properties_.find(before.id);
        if(found==properties_.end() || found->second!=before) return false;
    }
    return true;
}
bool RichonlineClassicProperty::commit_card_change(const CardChange& plan) noexcept {
    if(!matches(plan)) return false;
    // 所有地块先匹配；查找和已有元素的标量赋值不分配内存，不留下半次交换。
    for(const auto& after:plan.after()) properties_.find(after.id)->second=after;
    return true;
}
void RichonlineClassicProperty::advance_street_effects(std::uint64_t completed_rounds) {
    if(pending_ || !completed_rounds) throw CodecError("richonline_classic_street_round_invalid");
    if(completed_rounds==last_street_round_) return;
    if(last_street_round_==std::numeric_limits<std::uint64_t>::max() || completed_rounds!=last_street_round_+1)
        throw CodecError("richonline_classic_street_round_invalid");
    // 7E3480/7E35E0只递减正数；两个计时独立，均随日历推进，不发额外动画包。
    for(const auto id:ordinary_properties_) {
        auto& state=properties_.at(id);
        if(state.sealed_days) --state.sealed_days;
        if(state.price_rise_days) --state.price_rise_days;
    }
    last_street_round_=completed_rounds;
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
        auto part=target.kind==0 ? static_cast<std::uint32_t>(
            std::bit_cast<std::int32_t>(item.price*monetary_scale*coefficients[item.level])/1000) :
            monetary_scale*4000U;
        // 7E4140在有符号除法之后按该块D+5翻倍；7E42B0商店计数不读D+5。
        if(target.kind==0 && item.price_rise_days) part*=2U;
        total+=part;
        items.push_back({{"price",item.price},{"level",item.level},{"price_rise_days",item.price_rise_days}});
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
        if(property.owner!=entry.actor || property.level>=5 || property.kind==1 || entry.sealed || property.sealed_days)
            throw CodecError("richonline_classic_property_upgrade_ineligible");
        // 打开UI13前先证明所有可选许可证来源可处理，避免选了group1道具后才拒绝。
        if(property.sprite_type!=11 && (property.kind<2 || property.kind>6))
            validate_building_inventory(entry.actor);
        cost=property.sprite_type==11 ? 500 : 1500;
    }
    if(entry.land_equipment>0) cost/=2;
    const auto funds=ledger_->snapshot(entry.actor);
    if(funds.funds.cash>maximum_cash || funds.funds.cash<=cost)
        throw CodecError("richonline_classic_property_cash_ineligible");
    pending_=Pending{choice,entry,property,cost,now_()+timeout_};
    return request_opcode;
}
void RichonlineClassicProperty::validate_building_inventory(std::uint8_t actor) const {
    if(!buildings_) throw CodecError("richonline_classic_property_building_policy_missing");
    const auto& inventory=buildings_->cards.at(actor)->inventory();
    for(std::int8_t kind=2;kind<=6;++kind) {
        const auto licence=buildings_->resources->licence(kind);
        if(licence==-1) continue;
        bool found=false;
        for(const auto& slot:inventory) if(slot.card_id==licence && slot.count>0) {found=true;break;}
        if(!found && (!buildings_->secondary_licence_absent ||
            !buildings_->secondary_licence_absent(actor,licence)))
            throw CodecError("richonline_classic_building_secondary_inventory_unknown");
    }
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
    const bool select_building=accepted && pending.choice==RichonlineClassicPropertyChoice::upgrade &&
        pending.property.sprite_type!=11 && (pending.property.kind<2 || pending.property.kind>6);
    if(select_building) validate_building_inventory(pending.entry.actor);
    const auto next_deadline=select_building ? now_()+timeout_ : pending.deadline;
    const auto charged=accepted && !select_building ? pending.cost : 0U;
    auto after=pending.property;
    // 原版普通模式状态2只扣费，不移交产权/增级；不能在这里自动退款。
    if(accepted && !select_building && *pending.entry.status.possession!=2) {
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
            {"level",pending.property.level},{"possession",*pending.entry.status.possession},
            {"select_building",select_building}});
        const LuaValue expected{{"accepted",accepted},{"charged",charged},{"outcome",reason},
            {"owner",after.owner ? static_cast<int>(*after.owner) : -1},{"level",after.level},
            {"message",lua_bytes(View(message))}};
        if(plan!=expected || !plan.at("charged").is_number_integer() ||
            !plan.at("owner").is_number_integer() || !plan.at("level").is_number_integer())
            throw CodecError("lua_classic_property_choice_invalid");
    }
    RichonlineClassicPropertyResult result{std::move(message),pending.entry,pending.property,after,outcome,charged};
    if(select_building) result.continuation=RichonlineClassicPropertyContinuation::building_choice;
    auto after_funds=before_funds.funds;
    after_funds.cash-=charged;
    const std::array updates{RichonlineGameFundsUpdate{pending.entry.actor,before_funds,after_funds}};
    // 响应及Lua计划全部准备好后提交。账本先校验版本，回调只写标量且不反调账本。
    auto& state=properties_.at(pending.entry.property);
    if(!ledger_->commit_batch(updates,[&]() {
        if(state!=pending.property) return false;
        state=after;
        if(select_building) { pending_->building_choice=true;pending_->deadline=next_deadline; }
        else pending_.reset();
        return true;
    })) throw CodecError("richonline_classic_property_commit_stale");
    return result;
}
RichonlineClassicPropertyResult RichonlineClassicProperty::finish_building(std::int8_t requested,bool timed_out) {
    const auto pending=*pending_;
    if(!pending.building_choice || !buildings_)
        throw CodecError("richonline_classic_building_not_pending");
    const auto before_funds=ledger_->snapshot(pending.entry.actor);
    if(before_funds.funds.cash>maximum_cash) throw CodecError("richonline_classic_property_cash_invalid");
    // UI13原自动选择为3（贸易中心）；服务端超时长度仍是显式恢复策略。
    auto kind=timed_out ? std::int8_t{3} : requested;
    auto outcome=timed_out ? RichonlineClassicPropertyOutcome::timed_out :
        kind==-1 ? RichonlineClassicPropertyOutcome::declined : RichonlineClassicPropertyOutcome::accepted;
    const char* reason=timed_out ? "timed_out" : kind==-1 ? "declined" : "accepted";
    auto& cards=*buildings_->cards.at(pending.entry.actor);
    const auto inventory=cards.inventory();
    std::optional<RichonlinePlayerCards::PreparedConsumption> consumption;
    if(kind!=-1 && before_funds.funds.cash<=pending.cost) {
        kind=-1;outcome=RichonlineClassicPropertyOutcome::insufficient_funds;reason="insufficient_funds";
    }
    const auto licence=kind==-1 ? std::int16_t{-1} : buildings_->resources->licence(kind);
    if(licence!=-1) {
        for(std::int8_t slot=0;slot<8;++slot) {
            consumption=cards.prepare_consumption(slot,licence);
            if(consumption) break;
        }
        if(!consumption) {
            if(!buildings_->secondary_licence_absent ||
                !buildings_->secondary_licence_absent(pending.entry.actor,licence))
                throw CodecError("richonline_classic_building_secondary_inventory_unknown");
            kind=-1;outcome=RichonlineClassicPropertyOutcome::licence_missing;reason="licence_missing";
        }
    }
    const auto charged=kind==-1 ? 0U : pending.cost;
    auto after=pending.property;
    if(kind!=-1 && *pending.entry.status.possession!=2) { after.kind=kind;++after.level; }
    auto message=richonline_property_building_response(game_id_,kind);
    if(script_) {
        const auto plan=script_->call("property.classic_building",{{"game_id",game_id_},
            {"requested",requested},{"timed_out",timed_out},{"cash",before_funds.funds.cash},
            {"cost",pending.cost},{"licence_required",licence!=-1},{"licence_owned",consumption.has_value()},
            {"kind",pending.property.kind},{"level",pending.property.level},
            {"possession",*pending.entry.status.possession}});
        const LuaValue expected{{"selected",kind},{"charged",charged},{"outcome",reason},
            {"kind",after.kind},{"level",after.level},{"consume",consumption.has_value()},
            {"message",lua_bytes(View(message))}};
        if(plan!=expected || !plan.at("selected").is_number_integer() ||
            !plan.at("charged").is_number_integer() || !plan.at("kind").is_number_integer() ||
            !plan.at("level").is_number_integer()) throw CodecError("lua_classic_building_invalid");
    }
    RichonlineClassicPropertyResult result{std::move(message),pending.entry,pending.property,after,outcome,charged};
    auto after_funds=before_funds.funds;after_funds.cash-=charged;
    const std::array updates{RichonlineGameFundsUpdate{pending.entry.actor,before_funds,after_funds}};
    auto& state=properties_.at(pending.entry.property);
    // Lua、响应、库存计划均在提交前准备；同一回调扣许可证、写地产、清等待。
    if(!ledger_->commit_batch(updates,[&]() {
        if(state!=pending.property || cards.inventory()!=inventory) return false;
        if(consumption) cards.commit_inventory(consumption->remaining_inventory);
        state=after;pending_.reset();return true;
    })) throw CodecError("richonline_classic_building_commit_stale");
    return result;
}
RichonlineClassicPropertyResult RichonlineClassicProperty::handle(std::uint8_t sender_actor,View request,
    const RichonlineClassicPropertyEntry& current) {
    validate_pending(current);
    if(sender_actor!=pending_->entry.actor) throw CodecError("richonline_classic_property_sender_mismatch");
    if(pending_->building_choice) {
        const auto decoded=decode_richonline_property_building_request(request);
        if(decoded.calendar!=pending_->entry.calendar)
            throw CodecError("richonline_classic_property_calendar_mismatch");
        return finish_building(decoded.kind,now_()>=pending_->deadline);
    }
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
    if(pending_->building_choice) return finish_building(3,true);
    return finish(false,true);
}
}
