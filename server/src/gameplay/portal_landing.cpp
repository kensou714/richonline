#include "richonline_portal_landing.hpp"
#include <algorithm>

namespace richnet {
std::optional<RichonlinePortalLandingPlan> plan_richonline_portal_landing(std::uint16_t game,
    const RichonlineRoadTopology& topology,const std::optional<std::array<std::int16_t,2>>& pair,
    const RichonlineLandingContext& context,bool scripted_event_active) {
    const auto& source=topology.cell(context.position);
    if(source.static_type!=context.static_type || source.property_ref!=context.property_ref)
        throw CodecError("richonline_portal_landing_source_mismatch");
    if(context.static_type!=28 && context.static_type!=61) return {};
    const auto degree=std::count_if(source.neighbors.begin(),source.neighbors.end(),
        [](const auto& next) { return next.has_value(); });
    if(!source.walkable || context.game_mode!=3 || context.actor_slot>1 ||
        context.synthetic_actor!=(context.actor_slot==1) || degree==0 ||
        degree!=context.road_degree || (context.occupied_by_other_actor && !context.collision_resolved))
        throw CodecError("richonline_portal_landing_context_invalid");
    if(!pair) throw CodecError("richonline_portal_landing_pair_missing");
    if((*pair)[0]==(*pair)[1] || (context.position!=(*pair)[0] && context.position!=(*pair)[1]))
        throw CodecError("richonline_portal_landing_pair_invalid");
    for(const auto position:*pair) {
        const auto& endpoint=topology.cell(position);
        if(!endpoint.walkable || endpoint.static_type!=context.static_type)
            throw CodecError("richonline_portal_landing_pair_invalid");
    }
    Bytes confirmation;append_le(confirmation,0x4013,2);append_le(confirmation,game,2);
    append_le(confirmation,static_cast<std::uint16_t>(context.position),2);
    RichonlinePortalLandingPlan result{context,context.position,
        RichonlinePortalContinuation::property_phase2,std::move(confirmation)};
    if(scripted_event_active || context.actor_status.possession==7 ||
        context.actor_status.sleepwalking || context.actor_status.frozen) return result;
    result.authoritative_position=context.position==(*pair)[0] ? (*pair)[1] : (*pair)[0];
    result.continuation=RichonlinePortalContinuation::awaiting_server_continuation;
    return result;
}
}
