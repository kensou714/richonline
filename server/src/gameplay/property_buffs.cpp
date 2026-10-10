#include "richonline_boss_property.hpp"

#include <algorithm>
#include <limits>

namespace richnet {
RichonlineBuildingBuffRecipients RichonlineBossProperty::buff_recipients() const {
    // This owner represents one human against one BOSS, with no teammate.
    // Actor1480 is separate from the mutable alliance-card1472 countdown.
    return {{true,true},{{false,false},{false,false}}};
}
RichonlineBuildingBuffProperty RichonlineBossProperty::buff_property(std::int16_t ref,const Property& property) const {
    return {ref,property.owner,property.building.level,property.building.kind};
}
void RichonlineBossProperty::plan_buff_changes(PreparedCombat& plan,
    std::span<const RichonlineBuildingBuffChange> changes) const {
    plan.buffs_after_=plan_richonline_building_buff_changes(
        plan.buffs_after_ ? *plan.buffs_after_ : plan.expected_.buffs,changes,buff_recipients());
}
void RichonlineBossProperty::commit_buff_state(const RichonlineBuildingBuffState& after) noexcept {
    for(std::size_t kind=0;kind<2;++kind) {
        if(after.registrations[kind].size()!=building_buffs_.registrations[kind].size() ||
            after.actors[kind].size()!=building_buffs_.actors[kind].size()) std::terminate();
        std::copy(after.registrations[kind].begin(),after.registrations[kind].end(),building_buffs_.registrations[kind].begin());
        std::copy(after.actors[kind].begin(),after.actors[kind].end(),building_buffs_.actors[kind].begin());
    }
}
void RichonlineBossProperty::advance_building_buffs(std::uint64_t round,std::span<const bool> active,
    bool enabled,const GameLogSink& log) {
    if(deadline_ || active.size()!=2 || !buff_resources_)
        throw CodecError("richonline_property_buff_round_context_invalid");
    if(last_buff_round_ && round==*last_buff_round_) return;
    if((last_buff_round_ && (*last_buff_round_==std::numeric_limits<std::uint64_t>::max() ||
        round!=*last_buff_round_+1)) || property_revision_==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_property_buff_round_invalid");
    auto recipients=buff_recipients();
    for(std::size_t actor=0;actor<active.size();++actor) recipients.active[actor]=active[actor];
    std::vector<RichonlineBuildingBuffProperty> properties;
    properties.reserve(properties_.size());
    for(const auto& [ref,property]:properties_) properties.push_back(buff_property(ref,property));
    const auto plan=enabled ? plan_richonline_building_buff_round(building_buffs_,properties,recipients,*buff_resources_) :
        RichonlineBuildingBuffRound{building_buffs_,{}};
    std::vector<std::string> records;
    if(log) {
        records.push_back("richonline_building_buff_round round="+std::to_string(round)+
            " enabled="+std::to_string(enabled)+" activations="+std::to_string(plan.activations.size())+
            " zero_level_policy=wait-for-positive-level");
        for(const auto& event:plan.activations)
            records.push_back("richonline_building_buff_activated round="+std::to_string(round)+
                " kind="+std::string(event.kind==RichonlineBuildingBuffKind::defense ? "defense" : "attack")+
                " property="+std::to_string(event.property)+" owner="+std::to_string(event.owner)+
                " level="+std::to_string(event.level));
    }
    // Pure planning and allocation precede the serialized, scalar-only commit.
    commit_buff_state(plan.after);last_buff_round_=round;++property_revision_;
    if(log) for(const auto& record:records) log(record);
}
}
