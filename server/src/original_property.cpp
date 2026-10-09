#include "original_property.hpp"
#include <algorithm>
#include <type_traits>

namespace richnet {
namespace {
bool choices_enabled(const OriginalPropertyActor& actor) {
    return !actor.confused_god && !actor.sleepwalking && !actor.hibernating;
}
void validate_actor(const OriginalPropertyActor& actor) {
    validate_original_inventory(actor.inventory);
    for (const auto skill : actor.skills) if (skill > 7) throw CodecError("original_property_skill_invalid");
}
std::uint32_t purchase_price(const OriginalMapProperty& record, const OriginalPropertyActor& actor) {
    const auto price = static_cast<std::uint32_t>(record.price);
    return actor.purchase_discount ? price/2 : price;
}
OriginalPropertyStage after_upgrade(const OriginalMapProperty& record, const OriginalPropertyActor& actor) {
    if (record.kind == 11 && !actor.automated && choices_enabled(actor)) return OriginalPropertyStage::research;
    if (record.kind == 16) return OriginalPropertyStage::pyramid;
    return OriginalPropertyStage::complete;
}
std::uint8_t cap(const OriginalBuildingPolicy& policy, std::int8_t kind) {
    const auto value = policy.level_caps[static_cast<std::size_t>(kind-11)];
    if (!value) throw CodecError("original_property_map_cap_unrecovered");
    return *value;
}
}
OriginalBossProperties::OriginalBossProperties(std::uint16_t instance,
    std::shared_ptr<const OriginalMapResources> map, OriginalBuildingPolicy policy)
    : instance_(instance),map_(std::move(map)),policy_(policy) {
    if (!map_) throw CodecError("original_property_map_required");
    if (policy_.default_kind < 11 || policy_.default_kind > 20) throw CodecError("original_property_default_kind_invalid");
    for (const auto value : policy_.level_caps) if (value && *value > 7) throw CodecError("original_property_map_cap_invalid");
    records_ = map_->properties;
    for (const auto& record : records_) {
        if (record.id < 0 || record.owner < -1 || record.owner > 7 || record.level < 0 || record.level > 7 || record.price < 0)
            throw CodecError("original_property_record_invalid");
    }
}
OriginalPropertyStage OriginalBossProperties::begin(OriginalPropertyTurn turn, const OriginalPropertyActor& actor) {
    if (turn_) throw CodecError("original_property_decision_pending");
    if (turn.slot >= 8) throw CodecError("original_property_actor_invalid");
    validate_actor(actor);
    const auto road = std::find_if(map_->roads.begin(),map_->roads.end(),[&](const auto& item) { return item.tile == turn.tile; });
    if (road == map_->roads.end() || road->property_id < 0) throw CodecError("original_property_location_invalid");
    const auto record = std::find_if(records_.begin(),records_.end(),[&](const auto& item) { return item.id == road->property_id; });
    if (record == records_.end()) throw CodecError("original_property_id_missing");
    auto next = OriginalPropertyStage::complete;
    if (record->owner == -1) {
        if (choices_enabled(actor) && actor.funds.cash > purchase_price(*record,actor)) next = OriginalPropertyStage::purchase;
    } else if (record->owner != turn.slot && !turn.friendly_owner) {
        if (record->kind == 16) next = OriginalPropertyStage::pyramid;
    } else if (record->level == 0) {
        if (choices_enabled(actor)) next = OriginalPropertyStage::build;
    } else {
        if (record->kind < 11 || record->kind > 20) throw CodecError("original_property_kind_unsupported");
        const auto index = static_cast<std::size_t>(record->kind-11);
        next = choices_enabled(actor) && record->level < cap(policy_,record->kind) && record->level < actor.skills[index]
            ? OriginalPropertyStage::upgrade : after_upgrade(*record,actor);
    }
    record_index_ = static_cast<std::size_t>(record-records_.begin());
    stage_ = next;
    if (next != OriginalPropertyStage::complete) turn_ = turn;
    return next;
}
OriginalPropertyOutcome OriginalBossProperties::handle(const OriginalPropertyRequest& decision,
    const OriginalPropertyActor& actor, OriginalResearchQueue& research) {
    if (!turn_ || std::visit([](const auto& value) { return value.context; },decision) != turn_->context)
        throw CodecError("original_property_pending_context_mismatch");
    validate_actor(actor);
    auto message = encode_original_property_result(instance_,decision);
    auto updated = records_.at(record_index_);
    auto next_actor = actor;
    auto next = OriginalPropertyStage::complete;
    std::optional<std::int8_t> research_choice;
    std::visit([&](const auto& value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T,OriginalPropertyPurchase>) {
            if (stage_ != OriginalPropertyStage::purchase) throw CodecError("original_property_purchase_phase_invalid");
            if (value.parameter != 0) throw CodecError("original_property_purchase_parameter_unrecovered");
            if (value.choice == 1) {
                const auto admission_price = purchase_price(updated,actor);
                if (!choices_enabled(actor) || actor.funds.cash <= admission_price) throw CodecError("original_property_purchase_unavailable");
                // 716BC0 discounts admission for every kind; 4020 exempts kind10 only at settlement.
                const auto price = updated.kind == 10 ? static_cast<std::uint32_t>(updated.price) : admission_price;
                if (next_actor.funds.cash >= price) next_actor.funds.cash -= price;
                else {
                    const auto remaining = price-next_actor.funds.cash;
                    next_actor.funds.cash = 0;
                    next_actor.funds.deposit = remaining >= next_actor.funds.deposit ? 0U : next_actor.funds.deposit-remaining;
                }
                updated.owner = static_cast<std::int8_t>(turn_->slot);
            }
        } else if constexpr (std::is_same_v<T,OriginalBuildingChoice>) {
            if (stage_ != OriginalPropertyStage::build) throw CodecError("original_property_build_phase_invalid");
            if (value.choice != 10) {
                if (!choices_enabled(actor)) throw CodecError("original_property_build_unavailable");
                if (value.choice != policy_.default_kind) {
                    if (cap(policy_,value.choice) == 0)
                        throw CodecError("original_property_build_map_disabled");
                    const auto license = static_cast<std::int16_t>(value.choice+498);
                    const auto found = std::find_if(actor.inventory.begin(),actor.inventory.end(),
                        [license](const auto& slot) { return slot.id == license; });
                    if (found == actor.inventory.end()) throw CodecError("original_property_build_license_missing");
                    next_actor.inventory = remove_original_card(actor.inventory,
                        static_cast<std::uint8_t>(found-actor.inventory.begin()),1).inventory;
                }
                updated.kind = value.choice; updated.level = 1;
            }
        } else if constexpr (std::is_same_v<T,OriginalBossUpgrade>) {
            if (stage_ != OriginalPropertyStage::upgrade) throw CodecError("original_property_upgrade_phase_invalid");
            const auto index = static_cast<std::size_t>(updated.kind-11);
            if (value.choice == 1) {
                if (!choices_enabled(actor) || updated.level >= cap(policy_,updated.kind) || updated.level >= actor.skills[index])
                    throw CodecError("original_property_upgrade_unavailable");
                ++updated.level;
            }
            next = after_upgrade(updated,actor);
        } else if constexpr (std::is_same_v<T,OriginalResearchSelection>) {
            if (stage_ != OriginalPropertyStage::research) throw CodecError("original_property_research_phase_invalid");
            if (value.choice != -1) {
                if (actor.automated || !choices_enabled(actor)) throw CodecError("original_property_research_unavailable");
                research_choice = value.choice;
            }
        } else {
            throw CodecError("original_property_classic_upgrade_in_boss_mode");
        }
    },decision);
    std::vector<std::uint8_t> jobs;
    if (research_choice) jobs = research.schedule(turn_->slot,updated,*research_choice);
    OriginalPropertyOutcome result{std::move(message),std::move(next_actor),next,std::move(jobs)};
    records_[record_index_] = updated;
    stage_ = next;
    if (next == OriginalPropertyStage::complete) turn_.reset();
    return result;
}
void OriginalBossProperties::complete_pyramid(std::uint16_t context) {
    if (!turn_ || turn_->context != context || stage_ != OriginalPropertyStage::pyramid)
        throw CodecError("original_property_pyramid_completion_invalid");
    stage_ = OriginalPropertyStage::complete;
    turn_.reset();
}
}
