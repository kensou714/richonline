#pragma once
#include "richonline_actor_status.hpp"
#include "richonline_boss_cards.hpp"

namespace richnet {
enum class RichonlineMotionCard : std::uint16_t {
    turtle1039=104, reverse1040=105, stay1041=106, sleep1042=107, one_step1079=136, six_steps1084=141
};
struct RichonlineMotionCardRequest {
    RichonlineMotionCard kind;
    std::uint16_t calendar_counter;
    std::int8_t slot,bank,target_actor;
    std::uint8_t opaque7;
};
struct RichonlineMotionCardRules {
    std::uint8_t stay_turns,turtle_turns;
    std::uint8_t fixed_step_turns=0;
    std::uint8_t sleep_turns=0,alliance_turns=0;
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
    // Protected self-targets need explicit400B to recover controls.
    std::optional<Bytes> recovery;
    std::optional<std::uint8_t> movement_steps{};
};
RichonlineMotionCardRequest parse_richonline_motion_card(View);
RichonlineMotionCardPlan plan_richonline_motion_card(std::uint16_t game_id,
    const RichonlineMotionCardRequest&,std::uint16_t current_counter,std::int8_t active_actor,
    const RichonlineMotionCardTarget&,const RichonlineMotionCardRules&,
    const RichonlineRoadTopology&,const RichonlineRouteChooser&,const RichonlineBossCards&);
}
