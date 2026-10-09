#pragma once
#include "original_movement_wire.hpp"
#include "original_route.hpp"
#include "original_movement_bomb.hpp"

namespace richnet {
enum class OriginalMovePhase { ready, moving, landing, interrupted, direction };
enum class OriginalStopKind { landing, timed_bomb };
struct OriginalMovementEvent {
    OriginalStopKind kind;
    OriginalRoadCell cell;
    std::size_t travelled_steps;
    std::vector<std::int16_t> consumed_objects;
    OriginalBombPrediction bombs;
};
struct OriginalMovementResult {
    std::vector<Bytes> messages;
    std::optional<OriginalMovementEvent> event;
};
struct OriginalMovementWirePolicy {
    std::array<std::uint8_t,13> route_storage;
    Bytes landing_suffix, direction_suffix;
};
struct OriginalMovementSetup {
    std::uint16_t instance, context;
    std::int16_t tile;
    std::uint8_t direction, dice_count;
    OriginalMovementWirePolicy wire;
};
struct OriginalMovementEffects {
    OriginalRouteRules route;
    OriginalBombRoster bombs;
    bool allow_direction_choice;
};
struct OriginalMovementState {
    std::uint16_t context;
    std::int16_t tile;
    std::uint8_t direction, dice_count;
    OriginalMovePhase phase = OriginalMovePhase::ready;
    OriginalRouteTrace route;
    std::optional<OriginalMovementEvent> pending;
    std::optional<std::uint8_t> next_direction;
    bool direction_resolved = false;
};
class OriginalMovement final {
public:
    OriginalMovement(std::shared_ptr<const OriginalMapResources> map, OriginalMovementSetup setup,
        OriginalRouteRandom random);
    const OriginalMovementState& state() const noexcept { return state_; }
    const OriginalMovementEffects& effects() const noexcept { return effects_; }
    void set_effects(OriginalMovementEffects effects);
    OriginalMovementResult handle(const OriginalMovementRequest& request);
    OriginalMovementResult roll_faces(std::span<const std::uint8_t> faces, std::uint32_t gold_charge);
    bool wait_for_direction();
    void finish_landing();
    void finish_interruption();
    void begin_turn(std::uint16_t context);
    void relocate(std::int16_t tile, std::uint8_t direction);
private:
    std::shared_ptr<const OriginalMapResources> map_;
    OriginalMovementSetup setup_;
    OriginalRouteRandom random_;
    OriginalMovementState state_;
    OriginalMovementEffects effects_{{{},false,{},{}},{},false};
    std::optional<OriginalBombPrediction> bomb_prediction_;
    const OriginalRoadCell& cell(std::int16_t tile) const;
    OriginalMovementResult arrive(const OriginalMoveReport& report);
    OriginalMovementResult choose_direction(const OriginalDirectionChoice& choice);
    std::uint32_t draw(std::uint32_t upper) const;
    void clear_pending();
};
}
