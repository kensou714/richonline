#pragma once
#include "richonline_actor_status.hpp"
#include "richonline_boss_cards.hpp"

namespace richnet {
enum class RichonlineMotionCard : std::uint16_t { turtle1039=104, reverse1040=105, stay1041=106 };
struct RichonlineMotionCardRequest {
    RichonlineMotionCard kind;
    std::uint16_t calendar_counter;
    std::int8_t slot,bank,target_actor;
    std::uint8_t opaque7;
};
struct RichonlineMotionCardRules {
    std::uint8_t stay_turns,turtle_turns;
    static RichonlineMotionCardRules load(const std::filesystem::path& root);
};
struct RichonlineMotionCardTarget {
    std::int8_t actor;
    std::int16_t position;
    std::uint8_t heading;
    RichonlineActorStatus status;
    bool active;
    // NEW64FF10 excludes +1493/+1494/+1495/+1497 != -1 before selecting a target.
    bool in_target_selection;
};
enum class RichonlineMotionCardContinuation { resume_controls, await_same_position17 };
struct RichonlineMotionCardPlan {
    Bytes response;
    RichonlineBossCards::PreparedConsumption consumption;
    RichonlineMotionCardTarget before,after;
    RichonlineMotionCardContinuation continuation;
    bool blocked_by_protection;
    // Protected self-stay has no automatic 17 or6006 in40BA; explicit400B recovers controls.
    std::optional<Bytes> recovery;
};
RichonlineMotionCardRequest parse_richonline_motion_card(View);
RichonlineMotionCardPlan plan_richonline_motion_card(std::uint16_t game_id,
    const RichonlineMotionCardRequest&,std::uint16_t current_counter,std::int8_t active_actor,
    const RichonlineMotionCardTarget&,const RichonlineMotionCardRules&,
    const RichonlineRoadTopology&,const RichonlineRouteChooser&,const RichonlineBossCards&);
}
