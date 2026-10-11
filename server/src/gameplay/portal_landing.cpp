#include "richonline_portal_landing.hpp"
#include "richonline_boss_landing.hpp"
#include "lua_server.hpp"
#include "lua_wire.hpp"
#include <algorithm>

namespace richnet {
namespace {
bool supported_actor(const RichonlineLandingContext& context) {
    return (context.game_mode==0 && context.actor_slot<4 && !context.synthetic_actor) ||
        (context.game_mode==3 && context.actor_slot<=1 && context.synthetic_actor==(context.actor_slot==1));
}
bool collision_authorized(const RichonlineLandingContext& context) {
    // 经典宿主负责phase6：实际传送会跳过它，受控跳过传送则仍在原格执行。
    return !context.occupied_by_other_actor || context.collision_resolved ||
        (context.game_mode==0 && context.phase6_collision_authorized);
}
}
std::optional<RichonlinePortalLandingPlan> plan_richonline_portal_landing(std::uint16_t game,
    const RichonlineRoadTopology& topology,const std::optional<std::array<std::int16_t,2>>& pair,
    const RichonlineLandingContext& context,bool scripted_event_active) {
    const auto& source=topology.cell(context.position);
    if(source.static_type!=context.static_type || source.property_ref!=context.property_ref)
        throw CodecError("richonline_portal_landing_source_mismatch");
    if(context.static_type!=28 && context.static_type!=61) return {};
    const auto degree=std::count_if(source.neighbors.begin(),source.neighbors.end(),
        [](const auto& next) { return next.has_value(); });
    if(!source.walkable || !supported_actor(context) || degree==0 ||
        degree!=context.road_degree || !collision_authorized(context))
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
std::optional<RichonlinePortalLandingPlan> plan_richonline_random_teleport_landing(std::uint16_t game,
    const RichonlineRoadTopology& topology,const RichonlineLandingContext& context,bool scripted_event_active) {
    if(context.static_type!=58) return {};
    const auto& source=topology.cell(context.position);
    const auto degree=std::count_if(source.neighbors.begin(),source.neighbors.end(),
        [](const auto& next) {return next.has_value();});
    if(!source.walkable || source.static_type!=58 || source.property_ref!=context.property_ref ||
        context.property_ref!=-1 || !supported_actor(context) || degree==0 || degree!=context.road_degree ||
        !collision_authorized(context))
        throw CodecError("richonline_random_teleport_context_invalid");
    Bytes confirmation;append_le(confirmation,0x4013,2);append_le(confirmation,game,2);
    append_le(confirmation,static_cast<std::uint16_t>(context.position),2);
    RichonlinePortalLandingPlan result{context,context.position,
        RichonlinePortalContinuation::property_phase2,std::move(confirmation)};
    if(scripted_event_active || richonline_landing_controlled(context.actor_status)) return result;
    // BS_2_2 contains separate road components; teleportation may cross them.
    for(const auto& cell:topology.cells())
        if(cell.walkable && cell.position!=context.position &&
            std::any_of(cell.neighbors.begin(),cell.neighbors.end(),[](const auto& next){return next.has_value();}))
            result.random_destinations.push_back(cell.position);
    if(result.random_destinations.empty()) throw CodecError("richonline_random_teleport_destinations_missing");
    result.continuation=RichonlinePortalContinuation::random_teleport;
    return result;
}
RichonlinePortalMessages prepare_richonline_portal_messages(std::uint16_t game,std::string_view map,
    const RichonlinePortalLandingPlan& plan,std::optional<std::size_t> random_index,
    const std::shared_ptr<LuaServer>& script) {
    Bytes entrance;append_le(entrance,0x4013,2);append_le(entrance,game,2);
    append_le(entrance,static_cast<std::uint16_t>(plan.expected.position),2);
    if(plan.confirmation!=entrance || plan.expects_client_request())
        throw CodecError("richonline_portal_confirmation_invalid");
    const auto random=plan.continuation==RichonlinePortalContinuation::random_teleport;
    const auto paired=plan.continuation==RichonlinePortalContinuation::awaiting_server_continuation;
    if(random!=random_index.has_value() ||
        (random && (plan.expected.static_type!=58 || *random_index>=plan.random_destinations.size())) ||
        (paired && ((plan.expected.static_type!=28 && plan.expected.static_type!=61) ||
            plan.authoritative_position==plan.expected.position)) ||
        (!random && !paired && (plan.continuation!=RichonlinePortalContinuation::property_phase2 ||
            plan.authoritative_position!=plan.expected.position)))
        throw CodecError("richonline_portal_message_plan_invalid");
    RichonlinePortalMessages result{random ? plan.random_destinations[*random_index] : plan.authoritative_position,
        {std::move(entrance)}};
    if(random) {
        if(result.destination==plan.expected.position) throw CodecError("richonline_portal_random_destination_invalid");
        Bytes relocation;append_le(relocation,0x4209,2);append_le(relocation,game,2);
        append_le(relocation,static_cast<std::uint16_t>(result.destination),2);
        result.messages.push_back(std::move(relocation));
    }
    if(!script) return result;
    bool prepared=false,random_read=false,native_called=false;
    const auto kind=random ? "random" : paired ? "paired" : "skip";
    const LuaBindings api{{"tile.native",[&](const LuaValue&) {
        if(prepared || native_called) throw CodecError("lua_portal_native_already_called");
        native_called=true;return LuaValue(true);
    }},{"tile.portal.prepare",[&](const LuaValue&) {
        if(prepared || native_called) throw CodecError("lua_portal_already_prepared");
        prepared=true;
        return LuaValue{{"kind",kind},{"destination",plan.authoritative_position},
            {"destinations",plan.random_destinations}};
    }},{"tile.portal.random",[&](const LuaValue& args) {
        if(!prepared || random_read || !random_index ||
            args!=LuaValue{{"bound",plan.random_destinations.size()}})
            throw CodecError("lua_portal_random_invalid");
        random_read=true;return LuaValue(*random_index);
    }}};
    const auto response=script->call("tile.land",{{"type",plan.expected.static_type},
        {"position",plan.expected.position},{"actor",plan.expected.actor_slot},{"map",std::string(map)},
        {"game_id",game},{"portal_landing_available",true}},api);
    if(native_called) {
        if(response!=true) throw CodecError("lua_portal_native_response_invalid");
    } else {
        if(!prepared || random_read!=random_index.has_value() || !response.is_object() || response.size()!=2 ||
            !response.contains("destination") || !response.contains("messages") ||
            !response.at("destination").is_number_integer() || response.at("destination")!=result.destination)
            throw CodecError("lua_portal_response_invalid");
        const auto& packets=response.at("messages");
        if(!packets.is_array() || packets.size()!=result.messages.size()) throw CodecError("lua_portal_packets_invalid");
        std::vector<Bytes> scripted;
        for(const auto& packet:packets) scripted.push_back(lua_bytes(packet));
        if(scripted!=result.messages) throw CodecError("lua_portal_packets_mismatch");
        result.messages=std::move(scripted);
    }
    return result;
}
}
