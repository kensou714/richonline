#include "richonline_building_buffs.hpp"

#include <algorithm>
#include <bit>
#include <set>

namespace richnet {
namespace {
std::size_t index(RichonlineBuildingBuffKind kind) {
    switch(kind) {
    case RichonlineBuildingBuffKind::defense:return 0;
    case RichonlineBuildingBuffKind::attack:return 1;
    }
    throw CodecError("richonline_building_buff_kind_invalid");
}
std::int8_t byte_count(std::int32_t value) {
    return std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(value));
}
void validate(const RichonlineBuildingBuffState& state,const RichonlineBuildingBuffRecipients& recipients) {
    const auto count=recipients.active.size();
    if(count==0 || count>8 || recipients.shared.size()!=count || state.actors[0].size()!=count ||
        state.actors[1].size()!=count || state.registrations[0].size()!=state.registrations[1].size() ||
        state.registrations[0].size()>32767)
        throw CodecError("richonline_building_buff_snapshot_invalid");
    for(const auto& row:recipients.shared) if(row.size()!=count)
        throw CodecError("richonline_building_buff_relations_invalid");
    for(const auto& table:state.actors) for(const auto& buff:table)
        if(buff.property && (*buff.property<0 || buff.level>7))
            throw CodecError("richonline_building_buff_actor_snapshot_invalid");
    for(const auto& table:state.registrations) for(const auto& entry:table)
        if(entry.property < -1) throw CodecError("richonline_building_buff_property_invalid");
}
void validate(const RichonlineBuildingBuffProperty& property,std::size_t actors) {
    if(property.property<0 || property.level>7 || (property.owner && *property.owner>=actors))
        throw CodecError("richonline_building_buff_property_snapshot_invalid");
}
std::optional<RichonlineBuildingBuffKind> buff_kind(std::int8_t kind) {
    if(kind==13) return RichonlineBuildingBuffKind::defense;
    if(kind==14) return RichonlineBuildingBuffKind::attack;
    return {};
}
void clear_source(RichonlineBuildingBuffState& state,RichonlineBuildingBuffKind kind,
    std::int16_t property,std::optional<std::uint8_t> remaining_level,
    const RichonlineBuildingBuffRecipients& recipients) {
    auto& actors=state.actors[index(kind)];
    for(std::size_t holder=0;holder<actors.size();++holder) {
        if(!recipients.active[holder] || actors[holder].property!=property) continue;
        // NEW7CDD80/7CE090 return the first active holder, not the current owner.
        // A later holder is not consulted even if its cached level differs.
        if(remaining_level && actors[holder].level<=*remaining_level) return;
        actors[holder].property.reset();
        for(std::size_t actor=0;actor<actors.size();++actor)
            if(recipients.active[actor] && recipients.shared[holder][actor])
                actors[actor].property.reset();
        return;
    }
}
}
RichonlineBuildingBuffState make_richonline_building_buff_state(std::size_t properties,std::size_t actors) {
    if(properties>32767 || actors==0 || actors>8)
        throw CodecError("richonline_building_buff_capacity_invalid");
    RichonlineBuildingBuffState state;
    for(auto& table:state.registrations) table.resize(properties);
    for(auto& table:state.actors) table.resize(actors);
    return state;
}
bool register_richonline_building_buff(RichonlineBuildingBuffState& state,
    RichonlineBuildingBuffKind kind,std::int16_t property) {
    if(property<0) throw CodecError("richonline_building_buff_property_invalid");
    auto& table=state.registrations[index(kind)];
    const auto slot=std::find_if(table.begin(),table.end(),[](const auto& entry){return entry.property==-1;});
    if(slot==table.end()) return false;
    *slot={property,0};
    return true;
}
bool unregister_richonline_building_buff(RichonlineBuildingBuffState& state,
    RichonlineBuildingBuffKind kind,std::int16_t property) {
    if(property<0) throw CodecError("richonline_building_buff_property_invalid");
    auto& table=state.registrations[index(kind)];
    const auto slot=std::find_if(table.begin(),table.end(),[&](const auto& entry){return entry.property==property;});
    if(slot==table.end()) return false;
    slot->property=-1; // Native removal preserves the now-unused countdown byte.
    return true;
}
RichonlineBuildingBuffState plan_richonline_building_buff_changes(const RichonlineBuildingBuffState& before,
    std::span<const RichonlineBuildingBuffChange> changes,const RichonlineBuildingBuffRecipients& recipients) {
    validate(before,recipients);
    auto after=before;
    for(const auto& change:changes) {
        validate(change.before,recipients.active.size());
        validate(change.after,recipients.active.size());
        if(change.before.property!=change.after.property)
            throw CodecError("richonline_building_buff_change_property_mismatch");
        const auto property=change.after.property;
        const auto old_kind=buff_kind(change.before.kind),new_kind=buff_kind(change.after.kind);
        switch(change.kind) {
        case RichonlineBuildingBuffChangeKind::construction:
            if(change.before.level!=0 || change.after.level==0 || change.before.owner!=change.after.owner)
                throw CodecError("richonline_building_buff_construction_invalid");
            if(new_kind && change.after.owner) register_richonline_building_buff(after,*new_kind,property);
            break;
        case RichonlineBuildingBuffChangeKind::ownership:
            // NEW6806D0/680D60 remove old registrations only in mode4.
            if(new_kind && change.after.owner) register_richonline_building_buff(after,*new_kind,property);
            break;
        case RichonlineBuildingBuffChangeKind::conversion:
            if(change.before.owner!=change.after.owner)
                throw CodecError("richonline_building_buff_conversion_owner_invalid");
            if(old_kind) {
                unregister_richonline_building_buff(after,*old_kind,property);
                clear_source(after,*old_kind,property,{},recipients);
            }
            if(new_kind && change.after.owner) register_richonline_building_buff(after,*new_kind,property);
            break;
        case RichonlineBuildingBuffChangeKind::blast_downgrade:
            if(change.after.level>=change.before.level || change.before.owner!=change.after.owner ||
                (change.after.kind!=change.before.kind && (change.after.level!=0 || change.after.kind!=-1)))
                throw CodecError("richonline_building_buff_downgrade_invalid");
            // Projectile animations call both helpers regardless of the current
            // kind. Surviving registrations/buffs can belong to an older kind.
            for(const auto kind:{RichonlineBuildingBuffKind::defense,RichonlineBuildingBuffKind::attack}) {
                if(change.after.level==0) unregister_richonline_building_buff(after,kind,property);
                clear_source(after,kind,property,change.after.level,recipients);
            }
            break;
        default:throw CodecError("richonline_building_buff_change_kind_invalid");
        }
    }
    return after;
}
RichonlineBuildingBuffRound plan_richonline_building_buff_round(const RichonlineBuildingBuffState& before,
    std::span<const RichonlineBuildingBuffProperty> properties,const RichonlineBuildingBuffRecipients& recipients,
    const RichonlineCombatModifierResources& resources) {
    validate(before,recipients);
    const auto count=recipients.active.size();
    std::set<std::int16_t> ids;
    for(const auto& property:properties) {
        validate(property,count);
        if(!ids.insert(property.property).second)
            throw CodecError("richonline_building_buff_property_snapshot_invalid");
    }
    RichonlineBuildingBuffRound result{before,{}};
    for(const auto kind:{RichonlineBuildingBuffKind::defense,RichonlineBuildingBuffKind::attack}) {
        const auto table=index(kind);
        auto& actors=result.after.actors[table];
        for(std::size_t actor=0;actor<count;++actor) {
            auto& buff=actors[actor];
            if(recipients.active[actor] && buff.property && buff.rounds>0 && --buff.rounds==0)
                buff.property.reset();
        }
        for(auto& registration:result.after.registrations[table]) {
            if(registration.property==-1) continue;
            const auto found=std::find_if(properties.begin(),properties.end(),
                [&](const auto& value){return value.property==registration.property;});
            if(found==properties.end()) throw CodecError("richonline_building_buff_registered_property_missing");
            if(registration.rounds>0) --registration.rounds;
            if(registration.rounds!=0) continue;
            if(!found->owner) { registration.property=-1;continue; }
            // User policy: level0 has no initialized client resource. Keep the
            // registration due, but activate only after a positive level exists.
            if(found->level==0) continue;
            // Native keeps the table's effect even after a kind change if a duplicate
            // registration survived removal. Do not filter by the property's current kind.
            const auto& rule=resources.building_buff(table==0 ? 13 : 14,found->level);
            const RichonlineActiveBuildingBuff buff{found->property,found->level,byte_count(rule.duration)};
            const auto owner=*found->owner;
            actors[owner]=buff;
            for(std::size_t actor=0;actor<count;++actor)
                if(recipients.active[actor] && recipients.shared[owner][actor]) actors[actor]=buff;
            registration.rounds=byte_count(rule.period);
            result.activations.push_back({kind,found->property,owner,found->level});
        }
    }
    return result;
}
}
