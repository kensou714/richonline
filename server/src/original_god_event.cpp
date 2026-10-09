#include "original_god_event.hpp"

namespace richnet {
OriginalGodEvent::OriginalGodEvent(OriginalGodEventSetup setup) : setup_(setup) {
    if (setup_.actor >= 8) throw CodecError("original_god_event_actor_invalid");
    validate_original_god_state(setup_.transition.state);
    OriginalWealthOrigin origin;
    switch (setup_.transition.origin) {
    case OriginalGodOrigin::landing: origin = OriginalWealthOrigin::landing; break;
    case OriginalGodOrigin::card: origin = OriginalWealthOrigin::card; break;
    case OriginalGodOrigin::property: origin = OriginalWealthOrigin::property; break;
    default: throw CodecError("original_god_event_origin_invalid");
    }
    const auto kind = setup_.transition.state.kind;
    switch (setup_.transition.wait) {
    case OriginalGodWait::none: break;
    case OriginalGodWait::wealth:
        wealth_.begin({setup_.context,setup_.actor,kind,origin}); break;
    case OriginalGodWait::blessing:
        if (kind != 3) throw CodecError("original_god_event_kind_mismatch"); break;
    case OriginalGodWait::misfortune_cards:
        if (kind != 2) throw CodecError("original_god_event_kind_mismatch"); break;
    default: throw CodecError("original_god_event_wait_invalid");
    }
}
OriginalBlessingReward OriginalGodEvent::bless(const OriginalInventory& inventory, std::array<std::int16_t,2> cards,
    const OriginalCardCombinations& recipes, std::span<const std::int16_t> allowed_outputs) {
    if (setup_.transition.wait != OriginalGodWait::blessing) throw CodecError("original_god_blessing_not_pending");
    auto result = grant_original_blessing(inventory,setup_.instance,cards,recipes,allowed_outputs);
    setup_.transition.wait = OriginalGodWait::none;
    return result;
}
OriginalMisfortuneResult OriginalGodEvent::discard(const OriginalInventory& inventory, std::array<std::int8_t,4> slots) {
    if (setup_.transition.wait != OriginalGodWait::misfortune_cards) throw CodecError("original_god_misfortune_not_pending");
    auto result = apply_original_misfortune(inventory,setup_.instance,slots);
    setup_.transition.wait = OriginalGodWait::none;
    return result;
}
OriginalWealthOutcome OriginalGodEvent::settle(const OriginalWealthChoice& request,
    const OriginalWealthSnapshot& snapshot, std::int32_t amount) {
    if (setup_.transition.wait != OriginalGodWait::wealth) throw CodecError("original_god_wealth_not_pending");
    auto result = wealth_.resolve(request,snapshot,amount);
    if (!wealth_.awaiting_bankruptcy()) setup_.transition.wait = OriginalGodWait::none;
    return result;
}
void OriginalGodEvent::finish_bankruptcy(std::uint16_t context) {
    static_cast<void>(wealth_.finish_bankruptcy(context));
    setup_.transition.wait = OriginalGodWait::none;
}
OriginalGodOrigin OriginalGodEvent::finish() const {
    static_cast<void>(finish_original_god_transition(setup_.transition));
    return setup_.transition.origin;
}
}
