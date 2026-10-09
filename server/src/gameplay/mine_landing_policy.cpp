#include "richonline_mine_landing_policy.hpp"

#include <algorithm>

namespace richnet {
RichonlineMineLandingPolicy::RichonlineMineLandingPolicy(RichonlineRoadTopology topology,
    std::uint32_t mode,std::uint8_t local_slot,Preflight preflight)
    :topology_(std::move(topology)),mode_(mode),local_slot_(local_slot),preflight_(std::move(preflight)) {
    if(mode_!=3 || local_slot_>=2 || !preflight_ || topology_.cells().empty())
        throw CodecError("richonline_mine_landing_policy_invalid");
}
RichonlineMineLandingAdmission RichonlineMineLandingPolicy::assess(std::int16_t position,
    const RichonlineCombatSessionView& state) const {
    if(position<0 || static_cast<std::size_t>(position)>=topology_.cells().size())
        throw CodecError("richonline_mine_landing_position_invalid");
    const auto& cell=topology_.cell(position);
    if(!cell.walkable) return {false,"not_walkable"};
    if(cell.property_ref!=-1) return {false,"property_continuation_excluded"};
    if(topology_.portal_destination(position)) return {false,"portal_continuation_excluded"};
    switch(cell.static_type) {
    case -1:case 5:case 6:case 7:break;
    default:return {false,"static_continuation_excluded"};
    }
    if(std::ranges::any_of(state.dynamic_npcs,[position](const auto& object) {return object.position==position;}) ||
        std::ranges::any_of(state.mines.mines,[position](const auto& object) {return object.position==position;}))
        return {false,"ground_occupied"};
    std::uint8_t degree=0;
    for(const auto& neighbor:cell.neighbors) if(neighbor) ++degree;
    if(!degree) return {false,"road_isolated"};
    std::size_t active=0;
    for(std::size_t slot=0;slot<state.actors.size();++slot) if(state.actors[slot]) {
        const auto& actor=*state.actors[slot];
        if(actor.slot!=slot || slot>=2)
            throw CodecError("richonline_mine_landing_actor_invalid");
        if(!actor.active) continue;
        ++active;
    }
    if(!active) return {false,"no_active_actor"};
    for(const auto& actor:state.actors) if(actor && actor->active) {
        for(const auto& other:state.actors) if(other && other->active && other->slot!=actor->slot &&
            other->position==position) return {false,"actor_collision_excluded"};
        const RichonlineLandingContext context{actor->slot,position,cell.static_type,cell.property_ref,
            mode_,actor->slot!=local_slot_,degree,false,actor->status,false};
        try { preflight_(context); }
        catch(const CodecError& error) {return {false,std::string("preflight:")+error.what()};}
    }
    return {true,"closed_ground_then_static_landing"};
}
bool RichonlineMineLandingPolicy::supports(std::int16_t position,const RichonlineCombatSessionView& state) const {
    return assess(position,state).allowed;
}
std::vector<std::int16_t> RichonlineMineLandingPolicy::allowed_positions(const RichonlineCombatSessionView& state) const {
    std::vector<std::int16_t> result;
    for(const auto& cell:topology_.cells()) if(supports(cell.position,state)) result.push_back(cell.position);
    return result;
}
}
