#include "richonline_boss_property.hpp"
#include "richonline_boss_cards.hpp"
#include "richonline_construction_wire.hpp"
#include "lua_wire.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <utility>

namespace richnet {
void RichonlineBossProperty::configure_construction(std::array<std::int8_t,10> human_skills,
    std::shared_ptr<RichonlineBossCards> cards,std::shared_ptr<LuaServer> script) {
    if(pending_property_) throw CodecError("richonline_construction_configuration_pending");
    human_skills_=human_skills;
    cards_=std::move(cards);
    construction_script_=std::move(script);
}
Bytes RichonlineBossProperty::construction_message(const Property& property,std::int8_t requested,
    bool synthetic,std::int8_t resolved,int licence_slot) const {
    auto response=richonline_construction_response(game_id_,resolved);
    if(!construction_script_) return response;
    auto inventory=LuaValue::array();
    if(cards_) for(const auto& item:cards_->inventory())
        inventory.push_back({{"card",item.card_id},{"count",item.count}});
    const auto plan=construction_script_->call("property.construct",{{"game_id",game_id_},
        {"selection",requested},{"synthetic",synthetic},{"owner",property.owner ? *property.owner : -1},
        {"level",property.building.level},{"default_kind",construction_.default_kind},
        {"caps",construction_.scenario_caps},{"licences",construction_.licence_ids},{"inventory",inventory}});
    const LuaValue expected{{"selection",resolved},{"licence_slot",licence_slot},
        {"message",lua_bytes(View(response))}};
    if(plan!=expected) throw CodecError("lua_property_construction_invalid");
    return lua_bytes(plan.at("message"));
}
Bytes RichonlineBossProperty::upgrade_message(const Property& property,bool requested,bool synthetic,
    bool resolved) const {
    auto response=richonline_upgrade_response(game_id_,resolved);
    if(!construction_script_) return response;
    const auto kind=property.building.kind;
    const auto index=static_cast<std::size_t>(kind-11);
    const auto plan=construction_script_->call("property.upgrade",{{"game_id",game_id_},
        {"accept",requested},{"synthetic",synthetic},{"owner",property.owner ? *property.owner : -1},
        {"kind",kind},{"level",property.building.level},{"cap",construction_.scenario_caps.at(index)},
        {"skill",synthetic ? static_cast<int>(construction_.synthetic_skills.at(index)) :
            static_cast<int>(human_skills_.at(index))}});
    const char* continuation=!synthetic && kind==11 ? "research" : kind==16 ? "temple" :
        kind==15 ? "garden" : "complete";
    const LuaValue expected{{"accept",resolved},{"level",property.building.level+(resolved ? 1 : 0)},
        {"continuation",continuation},{"message",lua_bytes(View(response))}};
    if(plan!=expected) throw CodecError("lua_property_upgrade_invalid");
    return lua_bytes(plan.at("message"));
}
std::optional<RichonlineBossProperty::Building> RichonlineBossProperty::building(std::int16_t ref) const noexcept {
    const auto found=properties_.find(ref);
    return found==properties_.end() ? std::nullopt : std::optional{found->second.building};
}
RichonlineBossProperty::PreparedStreetEffect RichonlineBossProperty::prepare_street_card(
    std::int16_t ref,StreetEffect effect) const {
    const auto source=properties_.find(ref);
    if(source==properties_.end() || pending_property_)
        throw CodecError("richonline_street_card_property_invalid");
    if(effect!=StreetEffect::seal && effect!=StreetEffect::price_rise)
        throw CodecError("richonline_street_card_effect_invalid");
    const auto kind=source->second.building.kind;
    if(effect==StreetEffect::price_rise && (kind==8 || kind==9 || kind==10))
        throw CodecError("richonline_price_rise_card_property_protected");
    if(property_revision_==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_street_card_revision_exhausted");
    PreparedStreetEffect plan;plan.owner_=this;plan.revision_=property_revision_;plan.effect_=effect;
    for(const auto& [target,property]:properties_)
        if(property.street==source->second.street) plan.properties_.push_back(target);
    return plan;
}
bool RichonlineBossProperty::street_effect_matches(const PreparedStreetEffect& plan) const noexcept {
    return plan.owner_==this && plan.revision_==property_revision_ && !pending_property_;
}
bool RichonlineBossProperty::commit_street_effect(const PreparedStreetEffect& plan) noexcept {
    if(!street_effect_matches(plan)) return false;
    // NEW7E33A0/7E3510 write every property in the street, including unowned plots.
    // NEW7C0C50/7C6640 only tick/use these fields in classic mode, not mode3.
    for(const auto ref:plan.properties_) {
        auto& property=properties_.find(ref)->second;
        if(plan.effect_==StreetEffect::seal) property.sealed_days=5;
        else property.price_rise_days=5;
    }
    ++property_revision_;
    return true;
}
RichonlineLandingResult RichonlineBossProperty::owned_land(const RichonlineLandingContext& ctx,Property& property) {
    // 多个道路格可指向同一地产；等级只保存在共享地产记录中，不按道路格各存一份。
    Bytes stop;
    append_le(stop,0x4013,2); append_le(stop,game_id_,2);
    append_le(stop,static_cast<std::uint16_t>(ctx.position),2);
    RichonlineLandingResult result{{std::move(stop)},RichonlineLandingProgress::complete};
    const bool empty=property.building.level==0;
    // NEW7ACBC0 reads zero caps for kinds2..6 in the supported single-BOSS stage.
    if(!empty && property.building.kind>=2 && property.building.kind<=6) return result;
    if (!empty) {
        const auto index=static_cast<std::size_t>(property.building.kind-11);
        const auto skill=ctx.synthetic_actor ? static_cast<int>(construction_.synthetic_skills.at(index)) :
            static_cast<int>(human_skills_.at(index));
        if (property.building.level>=construction_.scenario_caps.at(index) || property.building.level>=skill) {
            if(!ctx.synthetic_actor && property.building.kind==11)
                return await_research(std::move(result.messages),ctx.property_ref);
            if(property.building.kind==16) return temple_result(ctx,property.building,true,std::move(result.messages));
            if(property.building.kind==15) return garden_result(ctx.actor_slot,property.building,std::move(result.messages));
            return result;
        }
    }
    if (ctx.synthetic_actor) {
        result.messages.push_back(empty ? construction_message(property,-1,true,construction_.default_kind,-1) :
            upgrade_message(property,true,true,true));
        if(!empty && property.building.kind==16) {
            auto upgraded=property.building;++upgraded.level;
            result=temple_result(ctx,upgraded,true,std::move(result.messages));
        }
        if(!empty && property.building.kind==15) {
            auto upgraded=property.building;++upgraded.level;
            result=garden_result(ctx.actor_slot,upgraded,std::move(result.messages));
        }
        std::optional<RichonlineBuildingBuffState> buffs;
        if(empty) {
            auto next=property;next.building={construction_.default_kind,1};
            const std::array changes{RichonlineBuildingBuffChange{RichonlineBuildingBuffChangeKind::construction,
                buff_property(ctx.property_ref,property),buff_property(ctx.property_ref,next)}};
            buffs=plan_richonline_building_buff_changes(building_buffs_,changes,buff_recipients());
            property.building.kind=construction_.default_kind;property.missile_rounds=0;
        }
        ++property.building.level;
        if(buffs) commit_buff_state(*buffs);
        ++property_revision_;
    } else {
        deadline_=now_()+timeout_;
        pending_property_=ctx.property_ref;
        if(!empty && property.building.kind==16) pending_temple_context_=ctx;
        decision_=empty ? Decision::construction : Decision::upgrade;
        result.progress=RichonlineLandingProgress::await_event;
        result.pending_opcode=empty ? 0x37 : 0x38;
    }
    return result;
}
RichonlineLandingResult RichonlineBossProperty::complete_construction(std::int8_t selection) {
    auto& property=properties_.at(*pending_property_);
    const auto requested=selection;
    int licence_slot=-1;
    // 新版 key120 请求值为 -1；显式解析为场景默认建筑，因为回复 403D(-1) 不会建造。
    if (selection==-1) selection=construction_.default_kind;
    auto inventory=cards_ ? cards_->inventory() : RichonlineChanceInventory{};
    if (selection!=10) {
        const auto index=static_cast<std::size_t>(selection-11);
        if (property.owner!=0 || property.building.level!=0 ||
            (selection!=construction_.default_kind && construction_.scenario_caps.at(index)==0))
            selection=10;
        else if (selection!=construction_.default_kind) {
            const auto licence=construction_.licence_ids.at(index);
            const auto slot=std::find_if(inventory.begin(),inventory.end(),[licence](const auto& item) {
                return item.card_id==licence && item.count>0;
            });
            if (!cards_ || slot==inventory.end()) selection=10;
            else {
                licence_slot=static_cast<int>(slot-inventory.begin());
                if (--slot->count==0) *slot={};
            }
        }
    }
    // 许可证扣除尚在副本中；Lua计划和完整403D通过复核后才提交建筑与库存。
    RichonlineLandingResult result{{construction_message(property,requested,false,selection,licence_slot)},
        RichonlineLandingProgress::complete};
    if (selection!=10) {
        auto next=property;next.building={selection,1};
        const std::array changes{RichonlineBuildingBuffChange{RichonlineBuildingBuffChangeKind::construction,
            buff_property(*pending_property_,property),buff_property(*pending_property_,next)}};
        const auto buffs=plan_richonline_building_buff_changes(building_buffs_,changes,buff_recipients());
        property.building={selection,1};
        property.missile_rounds=0;
        commit_buff_state(buffs);
        ++property_revision_;
        if (cards_) cards_->commit_inventory(inventory);
    }
    deadline_.reset(); pending_property_.reset();
    return result;
}
RichonlineLandingResult RichonlineBossProperty::complete_upgrade(bool accept) {
    // 新版 403E 只增加原建筑等级；此路径不扣现金、不再次消耗建筑许可证。
    auto& property=properties_.at(*pending_property_);
    if(property.building.kind<11 || property.building.kind>20)
        throw CodecError("richonline_upgrade_building_kind_invalid");
    const auto index=static_cast<std::size_t>(property.building.kind-11);
    const bool upgrade=accept && property.owner==0 && property.building.level>0 &&
        property.building.level<construction_.scenario_caps.at(index) && property.building.level<human_skills_.at(index);
    RichonlineLandingResult result{{upgrade_message(property,accept,false,upgrade)},RichonlineLandingProgress::complete};
    // 研究所升级后的下一个等待也先准备，时钟回调失败不能留下已升级、未续接的建筑。
    const auto research_deadline=property.building.kind==11 ? std::optional{now_()+timeout_} : std::nullopt;
    if(property.building.kind==16) {
        if(!pending_temple_context_) throw CodecError("richonline_temple_upgrade_context_missing");
        auto building=property.building;if(upgrade) ++building.level;
        result=temple_result(*pending_temple_context_,building,true,std::move(result.messages));
    }
    if(property.building.kind==15) {
        auto building=property.building;if(upgrade) ++building.level;
        result=garden_result(0,building,std::move(result.messages));
    }
    if (upgrade) { ++property.building.level; ++property_revision_; }
    if(research_deadline) {
        deadline_=research_deadline;decision_=Decision::research;
        result.progress=RichonlineLandingProgress::await_event;result.pending_opcode=0x39;
        return result;
    }
    deadline_.reset(); pending_property_.reset(); pending_temple_context_.reset();
    return result;
}
RichonlineLandingResult RichonlineBossProperty::await_research(std::vector<Bytes> messages,std::int16_t property) {
    deadline_=now_()+timeout_; pending_property_=property; decision_=Decision::research;
    return {std::move(messages),RichonlineLandingProgress::await_event,0x39};
}
RichonlineLandingResult RichonlineBossProperty::complete_research(std::int8_t selection) {
    const auto& property=properties_.at(*pending_property_);
    if(selection!=-1 && (property.owner!=0 || property.building.kind!=11 || selection>property.building.level))
        throw CodecError("richonline_research_choice_unavailable");
    auto next=research_jobs_;
    auto free_slots=LuaValue::array();
    for(std::size_t slot=0;slot<next.size();++slot) if(!next[slot]) free_slots.push_back(slot);
    auto scheduled=LuaValue::array();
    if(selection!=-1) {
        if(!cards_) throw CodecError("richonline_research_inventory_required");
        const auto& choice=research_choices_.at(static_cast<std::size_t>(selection-1));
        for(int cycle=1;cycle<=3;++cycle) {
            const auto free=std::find(next.begin(),next.end(),std::nullopt);
            if(free==next.end()) break;
            *free=ResearchJob{*pending_property_,selection,choice.card,
                std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(choice.days*cycle))};
            scheduled.push_back({{"slot",free-next.begin()},{"property",*pending_property_},
                {"choice",selection},{"card",choice.card},{"days",(*free)->days}});
        }
    }
    RichonlineLandingResult result{{richonline_research_response(game_id_,selection)},RichonlineLandingProgress::complete};
    if(construction_script_) {
        const auto choice=selection==-1 ? ResearchChoice{} : research_choices_.at(static_cast<std::size_t>(selection-1));
        const auto plan=construction_script_->call("property.research",{{"game_id",game_id_},
            {"selection",selection},{"property",*pending_property_},{"owner",property.owner ? *property.owner : -1},
            {"kind",property.building.kind},{"level",property.building.level},
            {"card",choice.card},{"days",choice.days},{"free_slots",free_slots}});
        const LuaValue expected{{"selection",selection},{"jobs",scheduled},
            {"message",lua_bytes(View(result.messages.front()))}};
        if(plan!=expected) throw CodecError("lua_property_research_invalid");
        result.messages.front()=lua_bytes(plan.at("message"));
    }
    research_jobs_=next; deadline_.reset(); pending_property_.reset(); return result;
}
std::size_t RichonlineBossProperty::pending_research_jobs() const noexcept {
    return static_cast<std::size_t>(std::count_if(research_jobs_.begin(),research_jobs_.end(),[](const auto& job){return job.has_value();}));
}
void RichonlineBossProperty::advance_research(std::uint8_t actor) {
    if(actor>1) throw CodecError("richonline_research_actor_invalid");
    auto next=research_jobs_;
    const auto before=cards_ ? cards_->inventory() : RichonlineChanceInventory{};
    try {
        for(auto& job:next) {
            if(!job) continue;
            const auto& property=properties_.at(job->property);
            if(property.building.kind!=11 || property.building.level<job->choice) { job.reset(); continue; }
            if(actor==0 && job->days>0) --job->days;
            if(job->days!=0) continue;
            if(!cards_) throw CodecError("richonline_research_inventory_required");
            try { cards_->commit_inventory(cards_->prepare_add(job->card)); }
            catch(const CodecError& error) {
                if(std::string_view(error.what())!="richonline_chance_inventory_full") throw;
            }
            job.reset();
        }
    } catch(...) { if(cards_) cards_->commit_inventory(before); throw; }
    research_jobs_=next;
}
}
