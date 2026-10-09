#pragma once
#include "richonline_chance_events.hpp"

namespace richnet {
struct RichonlineStatusRules {
    std::uint8_t fixed_step_turns;
    std::uint8_t turtle_turns;
    static RichonlineStatusRules parse(std::string_view gvalue);
    static RichonlineStatusRules load(const std::filesystem::path& root);
};
struct RichonlineActorStatus {
    std::uint8_t one_step=0, six_steps=0, turtle=0, stay=0, sleepwalking=0, frozen=0;
    float attack_multiplier=1.0F, damage_multiplier=1.0F;
    std::uint8_t attack_turns=0, damage_turns=0;
    bool protected_from_status=false;
    std::optional<std::int8_t> possession;
    std::optional<std::uint8_t> timed_bomb;
    // NEW64F2A0 clears the per-game Prop counters; 7CDAB0 increments1076
    // only after automatic protection succeeds. This is not a turn timer.
    std::uint16_t safety_helmet_uses=0;
    // Actor1492 is signed: -1 is a real neutral owner. A carried bomb requires
    // both fields; absence must never silently attribute its damage to slot0.
    std::optional<std::int8_t> timed_bomb_owner;
    bool operator==(const RichonlineActorStatus&) const = default;
};
// 7CD440 checks Prop1071 availability and activation before category10. This
// result belongs to shared inventory/card logic, not the chance module's RNG.
struct RichonlineSleepProtection {
    bool triggered;
    std::optional<std::uint8_t> consumed_inventory_slot;
};
enum class RichonlineStatusContinuation { local_phase2 };
struct RichonlineChanceStatusResult {
    Bytes packet;
    RichonlineActorStatus after;
    std::optional<std::uint8_t> consumed_inventory_slot;
    bool blocked_by_protection;
    bool detached_possession;
    bool removed_timed_bomb;
    RichonlineStatusContinuation continuation=RichonlineStatusContinuation::local_phase2;
};
// No parameters for categories7/8/9/16; duration for10/11; percentage,duration
// for12..15. Current status is owned by the turn/session layer.
RichonlineChanceStatusResult plan_richonline_chance_status(const RichonlineChanceEventTable&,
    std::string_view map,std::int32_t event,std::uint16_t game_id,
    std::span<const std::int32_t> parameters,const RichonlineActorStatus& before,
    const RichonlineStatusRules&,RichonlineSleepProtection sleep_protection,
    std::array<std::uint8_t,2> opaque6_7);
// Hooks mirror separate points in NEW4010/7C0C50; never decrement every actor
// on every message. The owner invokes each once in its matching phase.
void richonline_status_finish_previous_turn(RichonlineActorStatus&);
void richonline_status_begin_active_turn(RichonlineActorStatus&);
void richonline_status_begin_combat_phase(RichonlineActorStatus&);
}
