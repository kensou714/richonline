#include "richonline_classic_research.hpp"
#include "lua_wire.hpp"

#include <algorithm>
#include <bit>
#include <utility>

namespace richnet {
namespace {
// 同代客户端UI14预览A2A2B8和7E4C50消费表A2D938的有效1..5域一致。
constexpr std::array<std::int16_t,5> rewards{1062,1038,1044,1042,1063};
void validate_choice(std::int8_t choice) {
    if(choice!=-1 && (choice<1 || choice>5)) throw CodecError("richonline_classic_research_choice_invalid");
}
}
RichonlineClassicResearchRequest decode_richonline_classic_research_request(View request) {
    if(request.size()!=6) throw CodecError("richonline_classic_research_request_size");
    if(read_le(request.first(2))!=0x24) throw CodecError("richonline_classic_research_request_opcode");
    const auto choice=std::bit_cast<std::int8_t>(request[4]);
    validate_choice(choice);
    return {static_cast<std::uint16_t>(read_le(request.subspan(2,2))),choice,request[5]};
}
Bytes richonline_classic_research_response(std::uint16_t game_id,std::int8_t choice) {
    validate_choice(choice);
    Bytes packet;packet.reserve(5);
    append_le(packet,0x4026,2);append_le(packet,game_id,2);
    packet.push_back(static_cast<std::uint8_t>(choice));return packet;
}
RichonlineClassicResearch::RichonlineClassicResearch(std::uint16_t game_id,
    const RichonlineRoadTopology& topology,const RichonlinePropertyResources& map,
    std::shared_ptr<RichonlineClassicProperty> property,
    std::vector<std::shared_ptr<RichonlinePlayerCards>> cards,
    std::shared_ptr<const RichonlineChanceResources> resources,
    RichonlineClassicProperty::Now now,std::chrono::milliseconds timeout,std::shared_ptr<LuaServer> script)
    :game_id_(game_id),topology_(topology),property_(std::move(property)),cards_(std::move(cards)),
     resources_(std::move(resources)),now_(std::move(now)),timeout_(timeout),script_(std::move(script)) {
    if(!property_ || !resources_ || cards_.size()<2 || cards_.size()>4 || !now_ ||
        timeout_.count()<=0 || timeout_>std::chrono::minutes{10} ||
        map.width!=topology_.width() || map.height!=topology_.height())
        throw CodecError("richonline_classic_research_policy_invalid");
    for(std::size_t actor=0;actor<cards_.size();++actor) {
        const auto& cards_ref=cards_[actor];
        if(!cards_ref || cards_ref->game_id()!=game_id_ || cards_ref->actor_slot()!=actor ||
            cards_ref->game_mode()!=0 || cards_ref->map_name()!=cards_.front()->map_name())
            throw CodecError("richonline_classic_research_cards_mismatch");
    }
    for(const auto card:rewards) if(!resources_->contains_card(card))
        throw CodecError("richonline_classic_research_reward_missing");
    std::size_t large=0;
    for(const auto& item:map.properties) {
        const auto actual=property_->snapshot(item.id);
        if(actual.sprite_type!=item.sprite_type || actual.kind!=item.kind || actual.level!=item.level ||
            actual.owner!=item.owner || actual.price!=item.price)
            throw CodecError("richonline_classic_research_property_mismatch");
        if(item.sprite_type==12) ++large;
    }
    if(large>32767) throw CodecError("richonline_classic_research_capacity_invalid");
    // 7DF010按原始sprite12数量分配4N条，不是固定64，也不只数kind2。
    jobs_.resize(large*4);
}
bool RichonlineClassicResearch::registered(std::int16_t property,std::uint8_t actor) const noexcept {
    return std::any_of(jobs_.begin(),jobs_.end(),[&](const auto& job) {
        return job && job->property==property && job->actor==actor;
    });
}
void RichonlineClassicResearch::validate_entry(const RichonlineClassicPropertyEntry& entry) const {
    if(entry.game_id!=game_id_ || entry.actor>=cards_.size() || !entry.status.possession)
        throw CodecError("richonline_classic_research_actor_invalid");
    const auto& cell=topology_.cell(entry.position);
    const auto property=property_->snapshot(entry.property);
    if(!cell.walkable || cell.property_ref!=entry.property || property.owner!=entry.actor ||
        property.kind!=2 || property.level>5 || entry.sealed || property.sealed_days ||
        entry.status.possession==7 || entry.status.sleepwalking || entry.status.frozen)
        throw CodecError("richonline_classic_research_ineligible");
}
void RichonlineClassicResearch::begin(const RichonlineClassicPropertyEntry& entry) {
    if(pending_ || property_->active()) throw CodecError("richonline_classic_research_already_pending");
    validate_entry(entry);
    if(registered(entry.property,entry.actor)) throw CodecError("richonline_classic_research_already_registered");
    pending_=Pending{entry,property_->snapshot(entry.property),now_()+timeout_};
}
void RichonlineClassicResearch::validate_pending(const RichonlineClassicPropertyEntry& current) const {
    if(!pending_) throw CodecError("richonline_classic_research_not_pending");
    validate_entry(current);
    if(current!=pending_->entry || property_->snapshot(current.property)!=pending_->property || property_->active())
        throw CodecError("richonline_classic_research_stale");
}
RichonlineClassicResearchResult RichonlineClassicResearch::finish(std::int8_t requested,bool timed_out) {
    validate_choice(requested);
    const auto pending=*pending_;
    if(requested!=-1 && requested>pending.property.level)
        throw CodecError("richonline_classic_research_level_unavailable");
    // 服务端恢复策略采用合法取消；不把客户端自动选择2*b-1误当固定选项。
    auto choice=timed_out ? std::int8_t{-1} : requested;
    const auto free=std::find(jobs_.begin(),jobs_.end(),std::nullopt);
    std::optional<std::size_t> slot;
    if(choice!=-1 && free!=jobs_.end()) slot=static_cast<std::size_t>(free-jobs_.begin());
    else choice=-1;
    auto packet=richonline_classic_research_response(game_id_,choice);
    if(script_) {
        const auto plan=script_->call("property.classic_research_choice",{{"game_id",game_id_},
            {"requested",requested},{"timed_out",timed_out},{"level",pending.property.level},
            {"free_slot",free==jobs_.end() ? -1 : static_cast<int>(free-jobs_.begin())}});
        const LuaValue expected{{"choice",choice},{"slot",slot ? static_cast<int>(*slot) : -1},
            {"remaining",slot ? choice+1 : 0},{"message",lua_bytes(View(packet))}};
        if(plan!=expected || !plan.at("choice").is_number_integer() || !plan.at("slot").is_number_integer() ||
            !plan.at("remaining").is_number_integer()) throw CodecError("lua_classic_research_choice_invalid");
    }
    RichonlineClassicResearchResult result{std::move(packet),pending.entry,choice,slot,timed_out};
    if(slot) jobs_[*slot]=RichonlineClassicResearchJob{pending.entry.property,pending.entry.actor,
        static_cast<std::uint8_t>(choice),static_cast<std::uint8_t>(choice+1)};
    pending_.reset();return result;
}
RichonlineClassicResearchResult RichonlineClassicResearch::handle(std::uint8_t sender,View request,
    const RichonlineClassicPropertyEntry& current) {
    validate_pending(current);
    const auto decoded=decode_richonline_classic_research_request(request);
    if(sender!=pending_->entry.actor || decoded.calendar!=pending_->entry.calendar)
        throw CodecError("richonline_classic_research_sender_calendar_mismatch");
    return finish(decoded.choice,now_()>=pending_->deadline);
}
std::optional<RichonlineClassicResearchResult> RichonlineClassicResearch::poll(
    const RichonlineClassicPropertyEntry& current) {
    if(!pending_) return {};
    validate_pending(current);
    if(now_()<pending_->deadline) return {};
    return finish(-1,true);
}
RichonlineClassicResearchScan RichonlineClassicResearch::advance(std::uint8_t actor,std::uint64_t scan_id) {
    if(actor>=cards_.size() || !scan_id || scan_id<last_scan_ || pending_ || property_->active())
        throw CodecError("richonline_classic_research_scan_invalid");
    if(scan_id==last_scan_) {
        if(actor!=last_actor_) throw CodecError("richonline_classic_research_scan_actor_mismatch");
        return {0,0,0,true};
    }
    const auto before=jobs_;
    auto next=before;
    const auto inventory=cards_[actor]->inventory();
    auto after=inventory;
    std::vector<RichonlineClassicPropertyState> properties;
    auto input=LuaValue::array(),changes=LuaValue::array();
    RichonlineClassicResearchScan result;
    for(std::size_t index=0;index<next.size();++index) {
        auto& job=next[index];
        if(!job || job->actor!=actor) continue;
        const auto property=property_->snapshot(job->property);properties.push_back(property);
        input.push_back({{"slot",index},{"choice",job->choice},{"remaining",job->remaining_scans},
            {"kind",property.kind},{"level",property.level},{"owner",property.owner ? static_cast<int>(*property.owner) : -1}});
        const bool cancelled=property.kind!=2 || property.level<job->choice || property.owner!=actor;
        if(cancelled) {
            changes.push_back({{"slot",index},{"remaining",0},{"card",-1},{"cancelled",true}});
            job.reset();++result.cancelled;continue;
        }
        --job->remaining_scans;
        const auto card=job->remaining_scans ? std::int16_t{-1} : rewards[job->choice-1];
        changes.push_back({{"slot",index},{"remaining",job->remaining_scans},{"card",card},{"cancelled",false}});
        if(card!=-1) {
            // 按登记槽顺序插卡和合成；满手仍释放登记，不承诺以后补发。
            if(std::none_of(after.begin(),after.end(),[](const auto& slot){return slot.card_id==-1;}))
                ++result.discarded_full;
            after=resources_->add(cards_[actor]->map_name(),card,1,after);
            job.reset();++result.completed;
        }
    }
    if(script_) {
        const auto plan=script_->call("property.classic_research_scan",{{"actor",actor},{"jobs",input}});
        if(plan!=changes) throw CodecError("lua_classic_research_scan_invalid");
        for(const auto& change:plan)
            if(!change.at("slot").is_number_integer() || !change.at("remaining").is_number_integer() ||
                !change.at("card").is_number_integer()) throw CodecError("lua_classic_research_scan_invalid");
    }
    if(jobs_!=before || cards_[actor]->inventory()!=inventory)
        throw CodecError("richonline_classic_research_scan_stale");
    for(const auto& property:properties) if(property_->snapshot(property.id)!=property)
        throw CodecError("richonline_classic_research_scan_property_stale");
    // 所有可能失败的资源/Lua/快照检查先完成，之后队列与库存一次无抛提交。
    jobs_.swap(next);cards_[actor]->commit_inventory(after);
    last_scan_=scan_id;last_actor_=actor;return result;
}
void RichonlineClassicResearch::retire(std::uint8_t actor) noexcept {
    for(auto& job:jobs_) if(job && job->actor==actor) job.reset();
    if(pending_ && pending_->entry.actor==actor) pending_.reset();
}
void RichonlineClassicResearch::release_property(std::int16_t property,std::uint8_t actor) noexcept {
    for(auto& job:jobs_) if(job && job->property==property && job->actor==actor) {
        job.reset();return;
    }
}
}
