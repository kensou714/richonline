#include "original_boss_match.hpp"
#include <algorithm>

namespace richnet {
namespace {
void require_supported_building(std::int8_t kind) {
    if (kind == 16) throw CodecError("original_boss_match_pyramid_unimplemented");
    if (kind != 11) throw CodecError("original_boss_match_building_periodic_effects_unimplemented");
}
}
void OriginalBossMatch::begin_property(std::vector<Bytes>& replies) {
    const auto tile = movements_.at(current_).state().tile;
    const auto road = std::find_if(map_->roads.begin(),map_->roads.end(),[&](const auto& item) { return item.tile == tile; });
    if (road == map_->roads.end() || road->property_id < 0) throw CodecError("original_boss_match_property_location_invalid");
    const auto& records = properties_.records();
    const auto property = std::find_if(records.begin(),records.end(),[&](const auto& item) { return item.id == road->property_id; });
    if (property == records.end()) throw CodecError("original_boss_match_property_missing");
    if (property->owner >= 0 && property->owner != static_cast<std::int8_t>(current_) && property->level > 0 && property->kind != 11)
        throw CodecError(property->kind == 16 ? "original_boss_match_pyramid_unimplemented" :
            "original_boss_match_enemy_building_effects_unimplemented");
    if (property->level > 0) require_supported_building(property->kind);
    const auto stage = properties_.begin({action_context(),current_,tile,false},actors_.at(current_));
    if (stage == OriginalPropertyStage::complete) {
        complete_landing(replies);
        return;
    }
    phase_ = OriginalBossMatchPhase::property;
    continue_property(replies);
}
void OriginalBossMatch::property_result(const OriginalPropertyRequest& decision, std::vector<Bytes>& replies) {
    if (phase_ != OriginalBossMatchPhase::property) throw CodecError("original_boss_match_property_phase_invalid");
    if (const auto* build = std::get_if<OriginalBuildingChoice>(&decision); build && build->choice != 10)
        require_supported_building(build->choice);
    auto result = properties_.handle(decision,actors_.at(current_),research_);
    actors_.at(current_) = std::move(result.actor);
    replies.push_back(std::move(result.message));
    continue_property(replies);
}
void OriginalBossMatch::continue_property(std::vector<Bytes>& replies) {
    if (phase_ != OriginalBossMatchPhase::property) throw CodecError("original_boss_match_property_phase_invalid");
    switch (properties_.stage()) {
        case OriginalPropertyStage::complete:
            complete_landing(replies);
            return;
        case OriginalPropertyStage::pyramid:
            throw CodecError("original_boss_match_pyramid_unimplemented");
        case OriginalPropertyStage::research:
            if (current_ == 1) throw CodecError("original_boss_match_automated_research_unexpected");
            return;
        case OriginalPropertyStage::purchase:
            if (current_ == 1)
                property_result(OriginalPropertyPurchase{action_context(),0,1,policy_.wire.boss_purchase_opaque},replies);
            return;
        case OriginalPropertyStage::build:
            if (current_ == 1)
                property_result(OriginalBuildingChoice{action_context(),resources_.buildings.default_kind,policy_.wire.boss_choice_opaque},replies);
            return;
        case OriginalPropertyStage::upgrade:
            if (current_ == 1)
                property_result(OriginalBossUpgrade{action_context(),1,policy_.wire.boss_choice_opaque},replies);
            return;
    }
    throw CodecError("original_boss_match_property_stage_invalid");
}
}
