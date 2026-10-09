#pragma once

#include "richonline_combat_session.hpp"
#include "richonline_movement_wire.hpp"

namespace richnet {
struct RichonlineTimedBombRules {
    std::uint8_t movement_steps;
    static RichonlineTimedBombRules parse(std::string_view gvalue);
    static RichonlineTimedBombRules load(const std::filesystem::path& root);
};
struct RichonlineTimedBombRequest110 {
    std::uint16_t calendar_counter;
    std::int8_t inventory_slot,inventory_bank,target_actor;
    std::uint8_t opaque7;
};
RichonlineTimedBombRequest110 decode_richonline_timed_bomb110(View);
// NEW66E5A0 consumes the seven-byte prefix. Eight-byte output is an explicit
// emulator envelope; its last byte is caller supplied and has no known meaning.
Bytes encode_richonline_timed_bomb40be(std::uint16_t game,
    const RichonlineTimedBombRequest110&,std::uint8_t envelope_opaque7);

// Signed raw sentinels proven by NEW64FF10/7BE930. These are intentionally not
// renamed hospital/prison/frozen. Every existing actor needs an explicit view.
struct RichonlineTimedBombRawEligibility {
    std::int8_t actor1493,actor1494,actor1495,actor1497;
};
using RichonlineTimedBombEligibility=
    std::array<std::optional<RichonlineTimedBombRawEligibility>,8>;
RichonlineCombatTurnPlan prepare_richonline_timed_bomb_card(
    const RichonlineCombatSessionView&,const RichonlineCombatWorld&,
    std::uint8_t action_actor,const RichonlineTimedBombRequest110&,
    std::uint16_t expected_calendar,const RichonlineTimedBombRules&,
    const RichonlineTimedBombEligibility&,
    const RichonlineBossCards::PreparedConsumption&,std::uint8_t envelope_opaque7);

struct RichonlineTimedBombStepContext {
    std::uint8_t moving_actor,actor_count;
    std::int16_t actual_position;
    bool actor552,game83830_active;
    RichonlineTimedBombEligibility raw;
};
enum class RichonlineTimedBombStepOutcome { unchanged,counted,transferred,exploded };
enum class RichonlineTimedBombContinuationPolicy { timed_bomb_stop_then_landing };
struct RichonlineTimedBombStepPlan {
    RichonlineCombatTurnPlan combat;
    RichonlineTimedBombStepOutcome outcome;
    std::optional<std::uint8_t> transferred_to;
    std::optional<std::int8_t> exploding_owner;
    std::int16_t actual_stop;
};
// Called once per server-authenticated completed route step, before route1456
// advances. It mirrors client damage; it never emits an extra cash delta,
// repeats the bomb animation, or resumes the unused part of a4011 route.
RichonlineTimedBombStepPlan prepare_richonline_timed_bomb_step(
    const RichonlineCombatSessionView&,const RichonlineCombatWorld&,
    const RichonlineTimedBombStepContext&,RichonlineTimedBombContinuationPolicy);
// A0012 cannot itself decrement a timer. Authorize it only against the prepared
// explosion checkpoint before atomically committing and broadcasting its plan.
void validate_richonline_timed_bomb_ack12(const RichonlineTimedBombStepPlan&,
    const RichonlineMoveCountdown12&,std::uint16_t expected_calendar);

struct RichonlineTimedBombSegmentPlan {
    RichonlineCombatTurnPlan combat;
    std::uint8_t moving_actor;
    std::size_t accepted_steps;
    std::int16_t actual_stop;
    std::optional<std::int8_t> exploding_owner;
    std::vector<RichonlineTimedBombStepOutcome> outcomes;
};
// Inputs are the owner's verified completed positions, not a client-supplied
// route. The first explosion cuts off the remaining input. Empty input neither
// decrements nor explodes. All projected steps form one original-snapshot CAS.
RichonlineTimedBombSegmentPlan prepare_richonline_timed_bomb_segment(
    const RichonlineCombatSessionView&,const RichonlineCombatWorld&,std::uint8_t moving_actor,
    std::span<const RichonlineTimedBombStepContext>,RichonlineTimedBombContinuationPolicy);
void validate_richonline_timed_bomb_segment_ack12(const RichonlineTimedBombSegmentPlan&,
    const RichonlineMoveCountdown12&,std::uint16_t expected_calendar);
}
