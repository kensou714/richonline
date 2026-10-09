#pragma once

#include "original_building_resources.hpp"
#include "original_inventory.hpp"
#include "original_map.hpp"

namespace richnet {
struct OriginalResearchJob {
    std::int16_t property_id;
    std::uint8_t recipient;
    std::int8_t level;
    std::int16_t card;
    std::int8_t days;
    bool operator==(const OriginalResearchJob&) const = default;
};
using OriginalResearchJobs = std::array<std::optional<OriginalResearchJob>,64>;
using OriginalResearchInventories = std::array<OriginalInventory,8>;
struct OriginalResearchAdvanceInput {
    const OriginalResearchInventories& inventories;
    const OriginalCardCombinations& combinations;
    std::span<const std::int16_t> allowed_outputs;
};
struct OriginalResearchCompletion {
    std::uint8_t job_index;
    OriginalResearchJob job;
    std::optional<std::uint8_t> card_slot;
    std::vector<OriginalAppliedCombination> combinations;
};
struct OriginalResearchAdvanceResult {
    OriginalResearchInventories inventories;
    std::vector<OriginalResearchCompletion> completed;
    std::vector<std::uint8_t> cancelled;
};
class OriginalResearchQueue final {
public:
    explicit OriginalResearchQueue(std::array<OriginalResearchChoice,7> choices);
    std::vector<std::uint8_t> schedule(std::uint8_t recipient, const OriginalMapProperty& property, std::int8_t level);
    OriginalResearchAdvanceResult advance(std::uint8_t recipient, std::span<const OriginalMapProperty> properties,
                                         const OriginalResearchAdvanceInput& input);
    const OriginalResearchJobs& jobs() const noexcept { return jobs_; }
private:
    std::array<OriginalResearchChoice,7> choices_;
    OriginalResearchJobs jobs_{};
};
}
