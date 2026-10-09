#include "original_movement.hpp"
#include <algorithm>
#include <type_traits>

namespace richnet {
OriginalMovement::OriginalMovement(std::shared_ptr<const OriginalMapResources> map, OriginalMovementSetup setup,
    OriginalRouteRandom random) : map_(std::move(map)),setup_(std::move(setup)),random_(std::move(random)),
        state_{setup_.context,setup_.tile,setup_.direction,setup_.dice_count,OriginalMovePhase::ready,{},{},{},false} {
    if (!map_ || !random_) throw CodecError("original_movement_dependencies_required");
    cell(state_.tile);
    if (state_.direction > 3) throw CodecError("original_movement_direction_invalid");
    if (state_.dice_count < 1 || state_.dice_count > 3) throw CodecError("original_movement_dice_count_invalid");
    if (setup_.wire.landing_suffix.size() > 503 || setup_.wire.direction_suffix.size() > 504)
        throw CodecError("original_movement_plain_too_large");
}
const OriginalRoadCell& OriginalMovement::cell(std::int16_t tile) const {
    const auto found = std::find_if(map_->roads.begin(),map_->roads.end(),[tile](const auto& road) { return road.tile == tile; });
    if (found == map_->roads.end()) throw CodecError("original_movement_tile_not_walkable");
    return *found;
}
std::uint32_t OriginalMovement::draw(std::uint32_t upper) const {
    const auto value = random_(upper);
    if (value >= upper) throw CodecError("original_movement_random_out_of_range");
    return value;
}
void OriginalMovement::set_effects(OriginalMovementEffects effects) {
    if (state_.phase != OriginalMovePhase::ready) throw CodecError("original_movement_effects_while_pending");
    validate_original_bombs(effects.bombs);
    for (const auto& other : effects.bombs.others) if (other.active) cell(other.tile);
    effects_ = std::move(effects);
}
OriginalMovementResult OriginalMovement::handle(const OriginalMovementRequest& request) {
    return std::visit([this](const auto& value) -> OriginalMovementResult {
        if (value.context != state_.context) throw CodecError("original_movement_context_mismatch");
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T,OriginalRollRequest>) {
            if (state_.phase != OriginalMovePhase::ready) throw CodecError("original_movement_roll_while_pending");
            if (value.parameter != 0) throw CodecError("original_movement_roll_parameter_unrecovered");
            std::vector<std::uint8_t> faces;
            for (std::uint8_t index = 0; index < state_.dice_count; ++index)
                faces.push_back(static_cast<std::uint8_t>(draw(6)+1));
            return roll_faces(faces,0);
        } else if constexpr (std::is_same_v<T,OriginalMoveReport>) {
            return arrive(value);
        } else if constexpr (std::is_same_v<T,OriginalDiceChoice>) {
            if (value.count < 1 || value.count > 3) throw CodecError("original_movement_dice_count_invalid");
            state_.dice_count = static_cast<std::uint8_t>(value.count);
            return {};
        } else if constexpr (std::is_same_v<T,OriginalDirectionChoice>) {
            return choose_direction(value);
        } else { static_assert(!sizeof(T),"movement request alternative must be handled"); }
    },request);
}
OriginalMovementResult OriginalMovement::choose_direction(const OriginalDirectionChoice& choice) {
    if (state_.phase != OriginalMovePhase::direction) throw CodecError("original_movement_direction_not_pending");
    if (choice.direction < -1 || choice.direction > 3) throw CodecError("original_movement_direction_invalid");
    if (choice.direction != -1 && std::none_of(map_->edges.begin(),map_->edges.end(),[&](const auto& edge) {
        return edge.from == state_.tile && edge.direction == choice.direction && edge.direction != ((state_.direction+2U)%4U);
    })) throw CodecError("original_movement_direction_unavailable");
    const auto reply = encode_original_direction_result({setup_.instance,choice.direction,setup_.wire.direction_suffix});
    state_.next_direction.reset();
    if (choice.direction != -1) {
        state_.direction = static_cast<std::uint8_t>(choice.direction);
        state_.next_direction = state_.direction;
    }
    state_.direction_resolved = true;
    state_.phase = OriginalMovePhase::landing;
    return {{reply},{}};
}
bool OriginalMovement::wait_for_direction() {
    if (state_.phase == OriginalMovePhase::direction) return true;
    if (state_.phase != OriginalMovePhase::landing) throw CodecError("original_movement_direction_before_landing");
    if (!effects_.allow_direction_choice || state_.direction_resolved) return false;
    const auto neighbors = std::count_if(map_->edges.begin(),map_->edges.end(),[this](const auto& edge) { return edge.from == state_.tile; });
    if (neighbors <= 2) return false;
    state_.phase = OriginalMovePhase::direction;
    return true;
}
void OriginalMovement::clear_pending() {
    state_.phase = OriginalMovePhase::ready;
    state_.route.clear(); state_.pending.reset(); state_.direction_resolved = false;
    bomb_prediction_.reset();
}
void OriginalMovement::finish_landing() {
    if (state_.phase != OriginalMovePhase::landing) throw CodecError("original_movement_finish_without_landing");
    clear_pending();
}
void OriginalMovement::finish_interruption() {
    if (state_.phase != OriginalMovePhase::interrupted) throw CodecError("original_movement_finish_without_interruption");
    clear_pending();
}
void OriginalMovement::begin_turn(std::uint16_t context) {
    if (state_.phase != OriginalMovePhase::ready) throw CodecError("original_movement_turn_while_pending");
    state_.context = context;
}
void OriginalMovement::relocate(std::int16_t tile, std::uint8_t direction) {
    if (state_.phase != OriginalMovePhase::ready) throw CodecError("original_movement_relocate_while_pending");
    cell(tile);
    if (direction > 3) throw CodecError("original_movement_direction_invalid");
    if (state_.tile != tile || state_.direction != direction) state_.next_direction.reset();
    state_.tile = tile; state_.direction = direction;
}
}
