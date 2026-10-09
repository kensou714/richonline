#include "original_god_state.hpp"
#include "codec.hpp"
#include <algorithm>
#include <bit>
#include <cmath>

namespace richnet {
namespace {
std::int8_t byte_value(std::int64_t value) {
    return std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(value));
}
bool harmful(std::int8_t kind) { return kind == 1 || kind == 2 || kind == 6 || kind == 7; }
bool beneficial(std::int8_t kind) { return kind == 0 || kind == 3 || kind == 4; }
}
void validate_original_god_state(const OriginalGodState& state) {
    if (state.kind < -1 || state.kind > 7 || !std::isfinite(state.multiplier))
        throw CodecError("original_god_state_invalid");
}
OriginalGodState detach_original_god(const OriginalGodState& state) {
    validate_original_god_state(state);
    auto result = state;
    result.kind = -1; result.source = -1; result.days = 0;
    if (result.effect > 0) result.effect = 0;
    return result;
}
OriginalGodTick advance_original_god(const OriginalGodState& state) {
    validate_original_god_state(state);
    OriginalGodTick result{state,std::nullopt};
    if (state.kind == -1) return result;
    result.state.days = byte_value(static_cast<int>(state.days)-1);
    if (result.state.days <= 0) {
        result.expired_kind = state.kind;
        result.state = detach_original_god(result.state);
    }
    return result;
}
OriginalGodState attach_original_god(const OriginalGodState& state, std::int8_t kind, std::int8_t source,
                                    std::span<const std::int8_t,8> affix) {
    validate_original_god_state(state);
    if (kind < 0 || kind > 7) throw CodecError("original_god_kind_invalid");
    auto result = state;
    result.kind = kind; result.source = source; result.days = affix[static_cast<std::size_t>(kind)];
    return result;
}
OriginalGodState set_original_god_effect(const OriginalGodState& state, std::int32_t effect) {
    validate_original_god_state(state);
    auto result = state;
    result.effect = effect;
    switch (state.kind) {
    case 0: case 1: case 2: case 3:
        result.multiplier = static_cast<float>(effect)/100.0F;
        break;
    case 4: case 6: {
        const auto sum = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(effect)+100U);
        result.multiplier = static_cast<float>(sum)/100.0F;
        break;
    }
    default: result.multiplier = 0.0F; break;
    }
    return result;
}
OriginalGodTransition apply_original_pyramid(const OriginalGodState& state, std::int8_t level, bool friendly,
                                            bool player_state_active, const OriginalGodRules& rules) {
    validate_original_god_state(state);
    if (level < 1 || level > 7) throw CodecError("original_pyramid_level_invalid");
    if (rules.maximum_days < 0) throw CodecError("original_god_maximum_days_invalid");
    const auto& rule = rules.pyramid[static_cast<std::size_t>(level-1)];
    OriginalGodTransition result{state,OriginalGodOrigin::property,OriginalGodWait::none,false,false};
    if (state.kind == -1) {
        const auto kind = friendly ? rule.friendly_summon : rule.enemy_summon;
        if (kind == -1) return result;
        if (!(friendly ? beneficial(kind) : harmful(kind))) throw CodecError("original_pyramid_summon_invalid");
        result.state = attach_original_god(state,kind,2,rules.affix);
        result.attached = true;
        if (kind == 0 || kind == 1) result.wait = OriginalGodWait::wealth;
        else if (!player_state_active && kind == 2) result.wait = OriginalGodWait::misfortune_cards;
        else if (!player_state_active && kind == 3) result.wait = OriginalGodWait::blessing;
        return result;
    }
    const bool weaken = friendly ? harmful(state.kind) : beneficial(state.kind);
    const bool strengthen = friendly ? beneficial(state.kind) : harmful(state.kind);
    if (weaken) {
        const auto subtract = friendly ? rule.friendly_harmful_days : rule.enemy_beneficial_days;
        if (subtract <= 0) result.detached = true;
        else {
            result.state.days = byte_value(static_cast<std::int64_t>(state.days)-subtract);
            result.state.days = byte_value(static_cast<int>(result.state.days)-1);
            result.detached = result.state.days <= 0;
        }
        if (result.detached) result.state = detach_original_god(result.state);
    } else if (strengthen) {
        const auto days = friendly ? rule.friendly_beneficial_days : rule.enemy_harmful_days;
        const auto effect = friendly ? rule.friendly_beneficial_effect : rule.enemy_harmful_effect;
        if (days > 0) result.state.days = std::min(byte_value(static_cast<std::int64_t>(state.days)+days),rules.maximum_days);
        if (effect > 0) result.state = set_original_god_effect(result.state,effect);
    }
    return result;
}
OriginalGodState finish_original_god_transition(const OriginalGodTransition& transition) {
    if (transition.wait != OriginalGodWait::none) throw CodecError("original_god_followup_pending");
    validate_original_god_state(transition.state);
    return transition.state;
}
}
