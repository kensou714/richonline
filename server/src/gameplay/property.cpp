#include "richonline_boss_property.hpp"
#include "richonline_boss_stage.hpp"
#include "richonline_property_wire.hpp"
#include "richonline_construction_wire.hpp"
#include "richonline_property_resources.hpp"
#include "richonline_boss_landing.hpp"
#include "original_building_resources.hpp"
#include "original_god_resources.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace richnet {
namespace {
std::shared_ptr<RichonlineGameLedger> initial_ledger(std::array<std::uint32_t,2> cash) {
    for (const auto value:cash)
        if (value>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
            throw CodecError("richonline_boss_property_cash_out_of_range");
    return std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{
        {cash[0],{},0,{}},{cash[1],{},0,{}}});
}
RichonlinePropertyResources initial_properties(const std::filesystem::path& root,
    std::string_view map_name,const RichonlineRoadTopology& topology) {
    auto resources=load_richonline_property_resources(root,map_name);
    if (resources.width!=topology.width() || resources.height!=topology.height())
        throw CodecError("richonline_boss_property_resource_invalid");
    for (const auto& property:resources.properties) {
        // Current BOSS property combat/construction state represents a large
        // 2x2 building. Do not silently apply that shape to sprite11 resources.
        if (property.sprite_type!=12) throw CodecError("richonline_boss_property_sprite_unsupported");
        if (property.price==0) throw CodecError("richonline_boss_property_price_invalid");
        if (property.level>5 || (property.level==0 && property.kind!=-1) ||
            (property.level>0 && (property.kind<11 || property.kind>20)))
            throw CodecError("richonline_boss_property_building_unsupported");
    }
    return resources;
}
}
RichonlineBossProperty::RichonlineBossProperty(const std::filesystem::path& root,
    std::uint16_t game_id,std::array<std::uint32_t,2> initial_cash,const RichonlineBossStage& stage)
    : RichonlineBossProperty(root,game_id,initial_ledger(initial_cash),stage) {}
RichonlineBossProperty::RichonlineBossProperty(const std::filesystem::path& root,
    std::uint16_t game_id,std::shared_ptr<RichonlineGameLedger> ledger,const RichonlineBossStage& stage)
    : topology_(load_richonline_road_topology(root/"Map"/stage.map_name)),game_id_(game_id),
      ledger_(std::move(ledger)),construction_(RichonlineConstructionResources::load(root,stage)) {
    if (!ledger_ || ledger_->actor_count()!=2) throw CodecError("richonline_boss_property_ledger_invalid");
    if (stage.mode!=3 || stage.width!=topology_.width() || stage.height!=topology_.height())
        throw CodecError("richonline_boss_property_stage_mismatch");
    for (const auto& property:initial_properties(root,stage.map_name,topology_).properties)
        properties_.emplace(property.id,Property{property.price,property.owner,{property.kind,property.level},property.district,property.sprite_type});
    const auto research=load_original_research_resources(root/"Data"/"BwbValue.kpd");
    temple_rules_=original_pyramid_rules(research);
    for(std::size_t i=0;i<research_choices_.size();++i)
        research_choices_[i]={research.choices[i].card,research.choices[i].days};
}
std::array<std::uint32_t,2> RichonlineBossProperty::cash() const {
    return {ledger_->snapshot(0).funds.cash,ledger_->snapshot(1).funds.cash};
}
std::optional<std::uint8_t> RichonlineBossProperty::owner(std::int16_t ref) const noexcept {
    const auto found=properties_.find(ref);
    return found == properties_.end() ? std::nullopt : found->second.owner;
}
std::optional<std::uint32_t> RichonlineBossProperty::price(std::int16_t ref) const noexcept {
    const auto found=properties_.find(ref);
    return found == properties_.end() ? std::nullopt : std::optional{found->second.price};
}
bool RichonlineBossProperty::temple_supported(const RichonlineLandingContext& ctx,const Building& building,
    bool friendly) const {
    const auto& rule=temple_rules_.at(static_cast<std::size_t>(building.level-1));
    if(!ctx.actor_status.possession) {
        const auto npc=friendly ? rule.friendly_summon : rule.enemy_summon;
        return npc==-1 || (temple_aura_summons_ && (npc==4 || npc==6)) ||
            (npc>=0 && npc<4 && temple_higher_summons_[static_cast<std::size_t>(npc)]);
    }
    if(!temple_maximum_) return false;
    const auto npc=*ctx.actor_status.possession;
    const bool beneficial=npc==0 || npc==3 || (temple_aura_summons_ && npc==4);
    const bool harmful=npc==1 || npc==2 || npc==7 || (temple_aura_summons_ && npc==6);
    return beneficial || harmful;
}
RichonlineLandingResult RichonlineBossProperty::temple_result(const RichonlineLandingContext& ctx,
    const Building& building,bool friendly,std::vector<Bytes> messages) const {
    if(!temple_supported(ctx,building,friendly)) throw CodecError("richonline_temple_continuation_unsupported");
    RichonlineLandingResult result{std::move(messages),RichonlineLandingProgress::complete};
    const auto& rule=temple_rules_.at(static_cast<std::size_t>(building.level-1));
    if(ctx.actor_status.possession) {
        const auto npc=*ctx.actor_status.possession;
        const bool beneficial=npc==0 || npc==3 || npc==4;
        const bool extend=friendly ? beneficial : !beneficial;
        const auto days=friendly ? (extend ? rule.friendly_beneficial_days : rule.friendly_harmful_days) :
            (extend ? rule.enemy_harmful_days : rule.enemy_beneficial_days);
        result.temple_change=RichonlineTemplePossessionChange{ctx.actor_status,extend,days,*temple_maximum_};
        if(extend) result.temple_change->strength=
            friendly ? rule.friendly_beneficial_effect : rule.enemy_harmful_effect;
    } else {
        const auto summon=friendly ? rule.friendly_summon : rule.enemy_summon;
        if(summon!=-1) result.temple_change=RichonlineTemplePossessionChange{
            ctx.actor_status,false,0,*temple_maximum_,summon};
    }
    return result;
}
bool RichonlineBossProperty::validate_landing(const RichonlineLandingContext& ctx) const {
    const bool human = ctx.actor_slot == 0 && !ctx.synthetic_actor && static_cast<bool>(now_);
    const bool boss = ctx.actor_slot == 1 && ctx.synthetic_actor;
    if ((!human && !boss) || ctx.game_mode != 3 || ctx.position < 0 ||
        static_cast<std::size_t>(ctx.position) >= topology_.cells().size() ||
        (ctx.occupied_by_other_actor && !ctx.collision_resolved) || ctx.road_degree == 0 || ctx.road_degree > 4) return false;
    const auto found=properties_.find(ctx.property_ref);
    if (found == properties_.end()) return false;
    const auto& property=found->second;
    const auto& cell = topology_.cell(ctx.position);
    const auto degree = std::count_if(cell.neighbors.begin(),cell.neighbors.end(),[](const auto& next) { return next.has_value(); });
    // NEW phase2 checks the real road property reference, not chapter1's
    // artwork kind33..36. Chapter2/3 use different static road kinds.
    if (!cell.walkable || ctx.static_type != cell.static_type ||
        ctx.property_ref != cell.property_ref || degree != ctx.road_degree) return false;
    if (deadline_) throw CodecError("richonline_property_decision_already_pending");
    if (property.owner && property.building.kind==16 && property.building.level>0) {
        const bool friendly=*property.owner==ctx.actor_slot;
        if(!temple_supported(ctx,property.building,friendly)) return false;
        if(friendly && !richonline_landing_controlled(ctx.actor_status)) {
            const auto skill=ctx.synthetic_actor ? construction_.synthetic_skills[5] : human_skills_[5];
            if(property.building.level<construction_.scenario_caps[5] && property.building.level<skill) {
                auto upgraded=property.building;++upgraded.level;
                if(!temple_supported(ctx,upgraded,true)) return false;
            }
        }
    }
    return true;
}
std::optional<RichonlineLandingResult> RichonlineBossProperty::land(const RichonlineLandingContext& ctx) {
    if (!validate_landing(ctx)) return {};
    const bool human=ctx.actor_slot==0;
    auto& property=properties_.at(ctx.property_ref);
    // NEW7C6640 skips unowned purchase and self construction/upgrade under
    // control. Opponent effects stay in their own branches; never skip all land.
    if((!property.owner || *property.owner==ctx.actor_slot) && richonline_landing_controlled(ctx.actor_status)) {
        Bytes stop; append_le(stop,0x4013,2); append_le(stop,game_id_,2);
        append_le(stop,static_cast<std::uint16_t>(ctx.position),2);
        if(property.owner && property.building.kind==16 && property.building.level>0)
            return temple_result(ctx,property.building,true,{std::move(stop)});
        return RichonlineLandingResult{{std::move(stop)},RichonlineLandingProgress::complete};
    }
    if (property.owner) {
        if (*property.owner != ctx.actor_slot) {
            // NEW 7C6640 mode3 has no rent. Temple duration changes are committed
            // by the turn owner against its authoritative NPC clock.
            Bytes stop;
            append_le(stop,0x4013,2); append_le(stop,game_id_,2);
            append_le(stop,static_cast<std::uint16_t>(ctx.position),2);
            if(property.building.kind==16 && property.building.level>0)
                return temple_result(ctx,property.building,false,{std::move(stop)});
            return RichonlineLandingResult{{std::move(stop)},RichonlineLandingProgress::complete};
        }
        return owned_land(ctx,property);
    }
    Bytes stop;
    append_le(stop,0x4013,2); append_le(stop,game_id_,2);
    append_le(stop,static_cast<std::uint16_t>(ctx.position),2);
    RichonlineLandingResult result{{std::move(stop)},RichonlineLandingProgress::complete};
    const auto funds=ledger_->snapshot(ctx.actor_slot);
    if (funds.funds.cash > property.price) {
        if (human) {
            deadline_ = now_()+timeout_;
            pending_property_ = ctx.property_ref;
            decision_ = Decision::purchase;
            result.progress = RichonlineLandingProgress::await_event;
            result.pending_opcode = 0x20;
        } else {
            result.messages.push_back(richonline_property_response(game_id_,true));
            ledger_->adjust(1,funds,{-static_cast<std::int64_t>(property.price),0,0,0});
            property.owner = 1;
            ++property_revision_;
        }
    }
    return result;
}
void RichonlineBossProperty::enable_temple_possession(std::uint8_t maximum_days,bool aura_summons,
    std::array<bool,4> higher_summons) {
    if(!maximum_days || maximum_days>127) throw CodecError("richonline_temple_maximum_invalid");
    temple_maximum_=maximum_days;
    temple_aura_summons_=aura_summons;
    temple_higher_summons_=higher_summons;
}
void RichonlineBossProperty::enable_human_decisions(std::chrono::milliseconds timeout,Now now) {
    if (timeout.count() <= 0 || !now || deadline_) throw CodecError("richonline_property_timeout_invalid");
    timeout_ = timeout;
    now_ = std::move(now);
}
RichonlineLandingResult RichonlineBossProperty::complete_decision(bool accept) {
    if (!deadline_ || !pending_property_) throw CodecError("richonline_property_no_pending_decision");
    auto& property=properties_.at(*pending_property_);
    const auto funds=ledger_->snapshot(0);
    const bool purchase = accept && funds.funds.cash > property.price && !property.owner;
    RichonlineLandingResult result{{richonline_property_response(game_id_,purchase)},RichonlineLandingProgress::complete};
    if (purchase) {
        ledger_->adjust(0,funds,{-static_cast<std::int64_t>(property.price),0,0,0});
        property.owner = 0;
        ++property_revision_;
    }
    deadline_.reset();
    pending_property_.reset();
    return result;
}
RichonlineLandingResult RichonlineBossProperty::decide(View request) {
    // 由服务器保存的等待类型选择解析器，不能让客户端切换成另一种地产操作。
    if (!deadline_) throw CodecError("richonline_property_no_pending_decision");
    if(decision_==Decision::research) {
        const auto decoded=decode_richonline_research_request(request);
        return complete_research(now_()<*deadline_ ? decoded.selection : std::int8_t{-1});
    }
    if (decision_ == Decision::construction) {
        const auto decoded=decode_richonline_construction_request(request);
        return complete_construction(now_() < *deadline_ ? decoded.selection : std::int8_t{10});
    }
    if (decision_ == Decision::upgrade) {
        const auto decoded=decode_richonline_upgrade_request(request);
        return complete_upgrade(decoded.accept && now_() < *deadline_);
    }
    const auto decision = decode_richonline_property_request(request);
    return complete_decision(decision.accept && now_() < *deadline_);
}
std::optional<RichonlineLandingResult> RichonlineBossProperty::poll() {
    if (!deadline_ || now_() < *deadline_) return {};
    if(decision_==Decision::research) return complete_research(-1);
    if (decision_ == Decision::construction) return complete_construction(10);
    if (decision_ == Decision::upgrade) return complete_upgrade(false);
    return complete_decision(false);
}
RichonlineBossProperty::CombatSnapshot RichonlineBossProperty::combat_snapshot() const {
    CombatSnapshot result{property_revision_,{},deadline_.has_value()};
    result.buildings.reserve(properties_.size());
    const auto width=topology_.width();
    for (const auto& [ref,property]:properties_) {
        // NEW 7E4440 normalizes the four occupied tiles to the type12 lower
        // right anchor. These are property tiles, not adjacent road references.
        if (ref<0 || width==0 || static_cast<std::uint32_t>(ref)%width==0 ||
            static_cast<std::uint32_t>(ref)<width)
            throw CodecError("richonline_property_combat_footprint_invalid");
        const auto anchor=static_cast<std::int32_t>(ref);
        const auto row=static_cast<std::int32_t>(width);
        result.buildings.push_back({static_cast<std::uint32_t>(ref),
            {static_cast<std::int16_t>(anchor-row-1),static_cast<std::int16_t>(anchor-row),
             static_cast<std::int16_t>(anchor-1),ref},
            property.building.kind,property.building.level,property.owner,false});
    }
    return result;
}
RichonlineCombatBuildingView RichonlineBossProperty::combat_building_effect(
    const RichonlineCombatBuildingView& before,RichonlineBossBlastBuildingEffect effect) const {
    if (before.property>static_cast<std::uint32_t>(std::numeric_limits<std::int16_t>::max()) ||
        !properties_.contains(static_cast<std::int16_t>(before.property)))
        throw CodecError("richonline_property_combat_unknown_property");
    auto after=before;
    switch (effect) {
    case RichonlineBossBlastBuildingEffect::none: break;
    case RichonlineBossBlastBuildingEffect::remove_ownership: after.owner.reset(); break;
    case RichonlineBossBlastBuildingEffect::lower_one_level:
        if (!after.level) throw CodecError("richonline_property_combat_level_invalid");
        if (--after.level==0) after.kind=-1; // NEW 7E4020 type12, not type11 kind0.
        break;
    default: throw CodecError("richonline_property_combat_effect_invalid");
    }
    return after;
}
RichonlineBossProperty::PreparedCombat RichonlineBossProperty::prepare_combat(
    const CombatSnapshot& before,std::span<const RichonlineCombatBuildingView> after) const {
    const auto current=combat_snapshot();
    if (before.revision!=current.revision || before.decision_pending || current.decision_pending ||
        before.buildings!=current.buildings || after.size()!=before.buildings.size())
        throw CodecError("richonline_property_combat_stale");
    if (before.revision==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_property_combat_revision_overflow");
    PreparedCombat result;
    result.expected_=before;
    result.after_.assign(after.begin(),after.end());
    for (std::size_t i=0;i<after.size();++i) {
        const auto& old=before.buildings[i];
        const auto& next=after[i];
        if (next.property!=old.property || next.footprint!=old.footprint ||
            next.ownership_protected!=old.ownership_protected || next.level>old.level ||
            (next.owner && next.owner!=old.owner) ||
            (next.level>0 && next.kind!=old.kind) || (next.level==0 && next.kind!=-1))
            throw CodecError("richonline_property_combat_transition_invalid");
    }
    return result;
}
RichonlineBossProperty::PreparedCombat RichonlineBossProperty::prepare_house_card(
    std::int16_t position,std::uint8_t actor) const {
    PreparedCombat result;
    result.expected_=combat_snapshot();
    if(actor>=2 || result.expected_.decision_pending ||
        result.expected_.revision==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_house_card_state_invalid");
    result.after_=result.expected_.buildings;
    const auto found=std::ranges::find_if(result.after_,[position](const auto& building) {
        return std::ranges::find(building.footprint,position)!=building.footprint.end();
    });
    if(found==result.after_.end() || found->owner!=actor)
        throw CodecError("richonline_house_card_target_not_owned");
    if(found->level>=7) throw CodecError("richonline_house_card_maximum_level");
    if(found->kind==3 && found->level>=5) throw CodecError("richonline_house_card_building_cap");
    if(found->level>0 && found->kind!=3) {
        if(found->kind<11 || found->kind>20) throw CodecError("richonline_house_card_kind_invalid");
        const auto index=static_cast<std::size_t>(found->kind-11);
        const auto skill=actor==0 ? human_skills_.at(index) : construction_.synthetic_skills.at(index);
        if(found->level>=construction_.scenario_caps.at(index) || found->level>=skill)
            throw CodecError("richonline_house_card_building_cap");
    }
    if(found->level==0) found->kind=construction_.default_kind;
    ++found->level;
    return result;
}
RichonlineBossProperty::PreparedCombat RichonlineBossProperty::prepare_purchase_card(
    std::int16_t property_ref,std::uint8_t actor) const {
    PreparedCombat result;
    result.expected_=combat_snapshot();result.after_=result.expected_.buildings;
    if(property_ref<0 || actor>=2 || result.expected_.decision_pending ||
        result.expected_.revision==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_purchase_card_state_invalid");
    const auto found=std::ranges::find_if(result.after_,[property_ref](const auto& building) {
        return building.property==static_cast<std::uint32_t>(property_ref);
    });
    if(found==result.after_.end() || found->owner==actor ||
        found->kind==8 || found->kind==9 || found->kind==10)
        throw CodecError("richonline_purchase_card_target_invalid");
    found->owner=actor;
    return result;
}
RichonlineBossProperty::PreparedCombat RichonlineBossProperty::prepare_destruction_card(
    std::int16_t property_ref,std::uint8_t levels) const {
    if(property_ref<0 || (levels!=1 && levels!=5))
        throw CodecError("richonline_destruction_card_request_invalid");
    const auto before=combat_snapshot();
    auto after=before.buildings;
    const auto found=std::ranges::find_if(after,[property_ref](const auto& building) {
        return building.property==static_cast<std::uint32_t>(property_ref);
    });
    if(found==after.end() || found->level==0 || found->kind==8 || found->kind==9 || found->kind==10)
        throw CodecError("richonline_destruction_card_target_invalid");
    // NEW7E4020 clears type12 buildings to kind-1 when their level reaches zero.
    found->level=found->level>levels ? static_cast<std::uint8_t>(found->level-levels) : std::uint8_t{0};
    if(found->level==0) found->kind=-1;
    return prepare_combat(before,after);
}
RichonlineBossProperty::PreparedCombat RichonlineBossProperty::prepare_conversion_card(
    std::int16_t property_ref,std::int8_t kind,std::uint8_t actor) const {
    PreparedCombat result;
    result.expected_=combat_snapshot();
    if(property_ref<0 || kind<11 || kind>16 || actor>=2 || result.expected_.decision_pending ||
        result.expected_.revision==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_conversion_card_state_invalid");
    result.after_=result.expected_.buildings;
    const auto found=std::ranges::find_if(result.after_,[property_ref](const auto& building) {
        return building.property==static_cast<std::uint32_t>(property_ref);
    });
    if(found==result.after_.end() || !found->owner || found->level==0 || found->kind==kind ||
        (found->kind!=3 && (found->kind<11 || found->kind>20)))
        throw CodecError("richonline_conversion_card_target_invalid");
    const auto index=static_cast<std::size_t>(kind-11);
    const auto skill=actor==0 ? human_skills_.at(index) : construction_.synthetic_skills.at(index);
    if(skill<0 || skill>7) throw CodecError("richonline_conversion_card_skill_invalid");
    // NEW 6823A0 keeps the level, capped by the current actor's ability, even at zero.
    found->kind=kind;
    found->level=std::min(found->level,static_cast<std::uint8_t>(skill));
    return result;
}
RichonlineBossProperty::PreparedCombat RichonlineBossProperty::prepare_swap_card(
    std::int16_t source,std::int16_t target,bool buildings) const {
    PreparedCombat result;
    result.expected_=combat_snapshot();result.after_=result.expected_.buildings;
    if(source==target || result.expected_.decision_pending ||
        result.expected_.revision==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_swap_card_state_invalid");
    auto find=[&](std::int16_t ref) {
        return std::ranges::find_if(result.after_,[ref](const auto& b){return b.property==static_cast<std::uint32_t>(ref);});
    };
    const auto a=find(source),b=find(target);
    if(a==result.after_.end() || b==result.after_.end()) throw CodecError("richonline_swap_card_property_invalid");
    if(buildings) {
        std::swap(a->kind,b->kind);std::swap(a->level,b->level);
    } else {
        if(a->owner==b->owner) throw CodecError("richonline_swap_card_owner_equal");
        std::swap(a->owner,b->owner);
    }
    return result;
}
RichonlineBossProperty::PreparedCombat RichonlineBossProperty::prepare_growth_card(
    std::int16_t source,std::optional<std::uint8_t> owner,int levels) const {
    PreparedCombat result;
    result.expected_=combat_snapshot();result.after_=result.expected_.buildings;
    const auto origin=properties_.find(source);
    if((!owner && origin==properties_.end()) || (owner && *owner>=2) || levels==0 ||
        result.expected_.decision_pending || result.expected_.revision==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_growth_card_state_invalid");
    for(auto& b:result.after_) {
        const auto& property=properties_.at(static_cast<std::int16_t>(b.property));
        if(owner ? b.owner!=owner : property.street!=origin->second.street) continue;
        if(property.sprite_type==11 && b.kind==1) continue;
        if(levels<0) {
            b.level=b.level>-levels ? static_cast<std::uint8_t>(b.level+levels) : 0;
            if(!b.level && property.sprite_type==12) b.kind=-1;
        } else if(b.level<5) {
            // NEW7E3670 type12 creates kind3 on empty property.
            if(!b.level && property.sprite_type==12) b.kind=3;
            b.level=static_cast<std::uint8_t>(std::min(5,static_cast<int>(b.level)+levels));
        }
    }
    return result;
}
bool RichonlineBossProperty::combat_matches(const PreparedCombat& prepared) const noexcept {
    if (deadline_ || prepared.expected_.decision_pending || property_revision_!=prepared.expected_.revision ||
        prepared.expected_.buildings.size()!=properties_.size()) return false;
    for (const auto& entry:prepared.expected_.buildings) {
        const auto found=properties_.find(static_cast<std::int16_t>(entry.property));
        if (found==properties_.end() || found->second.owner!=entry.owner ||
            found->second.building.kind!=entry.kind || found->second.building.level!=entry.level) return false;
    }
    return true;
}
bool RichonlineBossProperty::commit_combat(const PreparedCombat& prepared) noexcept {
    if (!combat_matches(prepared)) return false;
    bool changed=false;
    for (const auto& entry:prepared.after_) {
        auto& property=properties_.find(static_cast<std::int16_t>(entry.property))->second;
        changed=changed || property.owner!=entry.owner || property.building.kind!=entry.kind ||
            property.building.level!=entry.level;
        property.owner=entry.owner;
        property.building={entry.kind,entry.level};
    }
    if (changed) ++property_revision_;
    return true;
}
}
