#include "original_research.hpp"
#include <algorithm>
#include <bit>
#include <map>

namespace richnet {
OriginalResearchQueue::OriginalResearchQueue(std::array<OriginalResearchChoice,7> choices) : choices_(choices) {
    for (const auto& choice : choices_) if (choice.card < 0) throw CodecError("original_research_choice_invalid");
}
std::vector<std::uint8_t> OriginalResearchQueue::schedule(std::uint8_t recipient, const OriginalMapProperty& property, std::int8_t level) {
    if (recipient >= 8) throw CodecError("original_research_recipient_invalid");
    if (property.id < 0 || property.kind != 11 || level < 1 || level > 7 || level > property.level)
        throw CodecError("original_research_choice_unavailable");
    const auto& choice = choices_[static_cast<std::size_t>(level - 1)];
    auto next = jobs_;
    std::vector<std::uint8_t> scheduled;
    const auto cycles = property.owner == static_cast<std::int8_t>(recipient) ? 3 : 1;
    for (int cycle = 1; cycle <= cycles; ++cycle) {
        const auto empty = std::find(next.begin(),next.end(),std::nullopt);
        if (empty == next.end()) break;
        const auto days = std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(static_cast<int>(choice.days)*cycle));
        *empty = OriginalResearchJob{property.id,recipient,level,choice.card,days};
        scheduled.push_back(static_cast<std::uint8_t>(empty-next.begin()));
    }
    jobs_ = next;
    return scheduled;
}
OriginalResearchAdvanceResult OriginalResearchQueue::advance(std::uint8_t recipient,
    std::span<const OriginalMapProperty> properties, const OriginalResearchAdvanceInput& input) {
    if (recipient >= 8) throw CodecError("original_research_recipient_invalid");
    for (const auto& inventory : input.inventories) validate_original_inventory(inventory);
    std::map<std::int16_t,const OriginalMapProperty*> by_id;
    for (const auto& property : properties)
        if (property.id < 0 || !by_id.emplace(property.id,&property).second) throw CodecError("original_research_property_invalid");
    auto next = jobs_;
    OriginalResearchAdvanceResult result{input.inventories,{},{}};
    for (std::uint8_t index = 0; index < next.size(); ++index) {
        auto& pending = next[index];
        if (!pending) continue;
        const auto found = by_id.find(pending->property_id);
        if (found == by_id.end()) throw CodecError("original_research_property_missing");
        const auto& property = *found->second;
        if (property.kind != 11 || property.level < pending->level) {
            pending.reset();
            result.cancelled.push_back(index);
            continue;
        }
        if (pending->recipient == recipient && pending->days > 0) --pending->days;
        if (pending->days != 0) continue;
        auto& inventory = result.inventories[pending->recipient];
        auto added = add_original_card(inventory,pending->card,1);
        OriginalResearchCompletion completed{index,*pending,added.slot,{}};
        if (added.slot) {
            auto combined = combine_original_cards(added.inventory,input.combinations,input.allowed_outputs);
            inventory = std::move(combined.inventory);
            completed.combinations = std::move(combined.applied);
        }
        result.completed.push_back(std::move(completed));
        pending.reset();
    }
    jobs_ = next;
    return result;
}
}
