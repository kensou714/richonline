#include "richonline_boss_property.hpp"
#include "richonline_boss_cards.hpp"
#include "richonline_construction_wire.hpp"

#include <algorithm>
#include <bit>
#include <utility>

namespace richnet {
void RichonlineBossProperty::configure_construction(std::array<std::int8_t,10> human_skills,
    std::shared_ptr<RichonlineBossCards> cards) {
    human_skills_=human_skills;
    cards_=std::move(cards);
}
std::optional<RichonlineBossProperty::Building> RichonlineBossProperty::building(std::int16_t ref) const noexcept {
    const auto found=properties_.find(ref);
    return found==properties_.end() ? std::nullopt : std::optional{found->second.building};
}
RichonlineLandingResult RichonlineBossProperty::owned_land(const RichonlineLandingContext& ctx,Property& property) {
    // 多个道路格可指向同一地产；等级只保存在共享地产记录中，不按道路格各存一份。
    Bytes stop;
    append_le(stop,0x4013,2); append_le(stop,game_id_,2);
    append_le(stop,static_cast<std::uint16_t>(ctx.position),2);
    RichonlineLandingResult result{{std::move(stop)},RichonlineLandingProgress::complete};
    const bool empty=property.building.level==0;
    if (!empty) {
        const auto index=static_cast<std::size_t>(property.building.kind-11);
        const auto skill=ctx.synthetic_actor ? static_cast<int>(construction_.synthetic_skills.at(index)) :
            static_cast<int>(human_skills_.at(index));
        if (property.building.level>=construction_.scenario_caps.at(index) || property.building.level>=skill) {
            if(!ctx.synthetic_actor && property.building.kind==11)
                return await_research(std::move(result.messages),ctx.property_ref);
            if(property.building.kind==16) return temple_result(ctx,property.building,true,std::move(result.messages));
            return result;
        }
    }
    if (ctx.synthetic_actor) {
        result.messages.push_back(empty ? richonline_construction_response(game_id_,construction_.default_kind) :
            richonline_upgrade_response(game_id_,true));
        if(!empty && property.building.kind==16) {
            auto upgraded=property.building;++upgraded.level;
            result=temple_result(ctx,upgraded,true,std::move(result.messages));
        }
        if (empty) property.building.kind=construction_.default_kind;
        ++property.building.level;
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
            else { if (--slot->count==0) *slot={}; }
        }
    }
    RichonlineLandingResult result{{richonline_construction_response(game_id_,selection)},RichonlineLandingProgress::complete};
    if (selection!=10) {
        property.building={selection,1};
        ++property_revision_;
        if (cards_) cards_->commit_inventory(inventory);
    }
    deadline_.reset(); pending_property_.reset();
    return result;
}
RichonlineLandingResult RichonlineBossProperty::complete_upgrade(bool accept) {
    // 新版 403E 只增加原建筑等级；此路径不扣现金、不再次消耗建筑许可证。
    auto& property=properties_.at(*pending_property_);
    const auto index=static_cast<std::size_t>(property.building.kind-11);
    const bool upgrade=accept && property.owner==0 && property.building.level>0 &&
        property.building.level<construction_.scenario_caps.at(index) && property.building.level<human_skills_.at(index);
    RichonlineLandingResult result{{richonline_upgrade_response(game_id_,upgrade)},RichonlineLandingProgress::complete};
    if(property.building.kind==16) {
        if(!pending_temple_context_) throw CodecError("richonline_temple_upgrade_context_missing");
        auto building=property.building;if(upgrade) ++building.level;
        result=temple_result(*pending_temple_context_,building,true,std::move(result.messages));
    }
    if (upgrade) { ++property.building.level; ++property_revision_; }
    if(property.building.kind==11)
        return await_research(std::move(result.messages),*pending_property_);
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
    if(selection!=-1) {
        if(!cards_) throw CodecError("richonline_research_inventory_required");
        const auto& choice=research_choices_.at(static_cast<std::size_t>(selection-1));
        for(int cycle=1;cycle<=3;++cycle) {
            const auto free=std::find(next.begin(),next.end(),std::nullopt);
            if(free==next.end()) break;
            *free=ResearchJob{*pending_property_,selection,choice.card,
                std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(choice.days*cycle))};
        }
    }
    RichonlineLandingResult result{{richonline_research_response(game_id_,selection)},RichonlineLandingProgress::complete};
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
