#pragma once
#include "richonline_boss_turns.hpp"

namespace richnet {
enum class RichonlinePortalContinuation { property_phase2, awaiting_server_continuation, random_teleport };
struct RichonlinePortalLandingPlan {
    RichonlineLandingContext expected;
    std::int16_t authoritative_position;
    RichonlinePortalContinuation continuation;
    Bytes confirmation;
    bool expects_client_request() const noexcept { return false; }
    // Deterministic candidate set; preflight must not consume the room RNG.
    std::vector<std::int16_t> random_destinations{};
};
// The caller supplies portals[0] for static28 or portals[1] for static61 from
// the active map's validated rule resources. This is a landing-only adapter.
// The turn owner must commit the new position and explicitly continue its turn;
// the absence of a client request does not close the server's pending event.
std::optional<RichonlinePortalLandingPlan> plan_richonline_portal_landing(
    std::uint16_t game,const RichonlineRoadTopology&,
    const std::optional<std::array<std::int16_t,2>>& pair,
    const RichonlineLandingContext&,bool scripted_event_active);
// Native policy for static58: choose another nonisolated road on the map.
// 4209 relocates without triggering effects at the destination.
std::optional<RichonlinePortalLandingPlan> plan_richonline_random_teleport_landing(
    std::uint16_t game,const RichonlineRoadTopology&,
    const RichonlineLandingContext&,bool scripted_event_active);
}
