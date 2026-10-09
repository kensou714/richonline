#pragma once
#include "original_building_resources.hpp"
#include "original_property_wire.hpp"
#include "original_research.hpp"
#include <memory>

namespace richnet {
enum class OriginalPropertyStage { purchase, build, upgrade, research, pyramid, complete };
struct OriginalPropertyActor {
    OriginalFunds funds;
    OriginalInventory inventory;
    std::array<std::uint8_t,10> skills;
    bool purchase_discount, automated, confused_god, sleepwalking, hibernating;
};
struct OriginalPropertyTurn {
    std::uint16_t context;
    std::uint8_t slot;
    std::int16_t tile;
    bool friendly_owner;
};
struct OriginalPropertyOutcome {
    Bytes message;
    OriginalPropertyActor actor;
    OriginalPropertyStage stage;
    std::vector<std::uint8_t> research_jobs;
};
class OriginalBossProperties final {
public:
    OriginalBossProperties(std::uint16_t instance, std::shared_ptr<const OriginalMapResources> map,
        OriginalBuildingPolicy policy);
    OriginalPropertyStage begin(OriginalPropertyTurn turn, const OriginalPropertyActor& actor);
    OriginalPropertyOutcome handle(const OriginalPropertyRequest& decision,
        const OriginalPropertyActor& actor, OriginalResearchQueue& research);
    void complete_pyramid(std::uint16_t context);
    OriginalPropertyStage stage() const noexcept { return stage_; }
    const std::vector<OriginalMapProperty>& records() const noexcept { return records_; }
private:
    std::uint16_t instance_;
    std::shared_ptr<const OriginalMapResources> map_;
    OriginalBuildingPolicy policy_;
    std::vector<OriginalMapProperty> records_;
    std::optional<OriginalPropertyTurn> turn_;
    std::size_t record_index_ = 0;
    OriginalPropertyStage stage_ = OriginalPropertyStage::complete;
};
}
