#include "original_movement.hpp"
#include <algorithm>
#include <set>

namespace richnet {
OriginalMovementResult OriginalMovement::roll_faces(std::span<const std::uint8_t> faces, std::uint32_t gold_charge) {
    if (state_.phase != OriginalMovePhase::ready) throw CodecError("original_movement_roll_while_pending");
    if (faces.empty() || faces.size() > 3 || std::any_of(faces.begin(),faces.end(),[](auto face) { return face < 1 || face > 6; }))
        throw CodecError("original_movement_faces_invalid");
    std::uint8_t sum = 0;
    for (auto face : faces) sum = static_cast<std::uint8_t>(sum+face);
    auto rules = effects_.route;
    rules.first_direction = state_.next_direction;
    auto trace = build_original_route(map_,{state_.tile,state_.direction,sum,std::move(rules)},random_);
    if (trace.empty()) throw CodecError("original_movement_route_empty");
    auto prediction = predict_original_bombs(effects_.bombs,trace);
    OriginalRollRoute route{setup_.instance,state_.tile,static_cast<std::uint8_t>(faces.size()),{0,0,0},{},setup_.wire.route_storage,gold_charge};
    std::copy(faces.begin(),faces.end(),route.faces.begin());
    for (const auto& step : trace) route.directions.push_back(step.direction);
    const auto reply = encode_original_roll_route(route);
    state_.phase = OriginalMovePhase::moving;
    state_.route = std::move(trace);
    bomb_prediction_ = std::move(prediction);
    state_.next_direction.reset();
    return {{reply},{}};
}
OriginalMovementResult OriginalMovement::arrive(const OriginalMoveReport& report) {
    if (state_.phase != OriginalMovePhase::moving) throw CodecError("original_movement_report_without_route");
    const auto explosion = bomb_prediction_->explosion_step;
    std::size_t travelled = state_.route.size();
    OriginalStopKind kind;
    switch (report.kind) {
    case OriginalMoveKind::normal:
        if (explosion) throw CodecError("original_movement_expected_bomb_report");
        if (report.tile != state_.route.back().tile) throw CodecError("original_movement_endpoint_mismatch");
        kind = OriginalStopKind::landing;
        break;
    case OriginalMoveKind::special:
        if (!explosion || report.tile != state_.route[*explosion-1U].tile) throw CodecError("original_movement_unexpected_bomb_report");
        travelled = *explosion;
        kind = OriginalStopKind::timed_bomb;
        break;
    default: throw CodecError("original_movement_report_kind_invalid");
    }
    OriginalMovementEvent event{kind,cell(report.tile),travelled,{},*bomb_prediction_};
    std::set<std::int16_t> consumed;
    for (std::size_t index = 0; index < travelled; ++index) {
        const auto tile = state_.route[index].tile;
        const auto found = effects_.route.objects.find(tile);
        if (found != effects_.route.objects.end() && (found->second == 11 || found->second == 30)) consumed.insert(tile);
    }
    event.consumed_objects.assign(consumed.begin(),consumed.end());
    OriginalMovementResult result{{},event};
    if (kind == OriginalStopKind::landing)
        result.messages.push_back(encode_original_landing({setup_.instance,report.tile,setup_.wire.landing_suffix}));
    state_.tile = report.tile;
    state_.direction = state_.route[travelled-1U].direction;
    state_.pending = event;
    state_.phase = kind == OriginalStopKind::landing ? OriginalMovePhase::landing : OriginalMovePhase::interrupted;
    effects_.bombs = bomb_prediction_->after;
    for (const auto tile : consumed) effects_.route.objects.erase(tile);
    return result;
}
}
