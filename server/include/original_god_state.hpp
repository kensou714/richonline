#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace richnet {
struct OriginalGodState {
    std::int8_t kind, source, days;
    std::int32_t effect;
    float multiplier;
    bool operator==(const OriginalGodState&) const = default;
};
struct OriginalPyramidRule {
    std::int8_t enemy_summon, friendly_summon;
    std::int32_t enemy_harmful_days, enemy_harmful_effect, friendly_harmful_days, friendly_harmful_effect;
    std::int32_t enemy_beneficial_days, enemy_beneficial_effect, friendly_beneficial_days, friendly_beneficial_effect;
};
struct OriginalGodRules {
    std::array<std::int8_t,8> affix;
    std::array<OriginalPyramidRule,7> pyramid;
    std::int8_t maximum_days;
};
enum class OriginalGodOrigin { landing, card, property };
enum class OriginalGodWait { none, wealth, blessing, misfortune_cards };
struct OriginalGodTransition {
    OriginalGodState state;
    OriginalGodOrigin origin;
    OriginalGodWait wait;
    bool attached, detached;
};
struct OriginalGodTick {
    OriginalGodState state;
    std::optional<std::int8_t> expired_kind;
};
void validate_original_god_state(const OriginalGodState& state);
OriginalGodTick advance_original_god(const OriginalGodState& state);
OriginalGodState detach_original_god(const OriginalGodState& state);
OriginalGodState attach_original_god(const OriginalGodState& state, std::int8_t kind, std::int8_t source,
                                    std::span<const std::int8_t,8> affix);
OriginalGodState set_original_god_effect(const OriginalGodState& state, std::int32_t effect);
OriginalGodTransition apply_original_pyramid(const OriginalGodState& state, std::int8_t level, bool friendly,
                                            bool player_state_active, const OriginalGodRules& rules);
OriginalGodState finish_original_god_transition(const OriginalGodTransition& transition);
}
