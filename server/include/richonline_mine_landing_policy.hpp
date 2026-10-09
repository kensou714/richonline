#pragma once

#include "richonline_combat_session.hpp"

namespace richnet {
struct RichonlineMineLandingAdmission {
    bool allowed;
    std::string reason;
};
// Capability filter for the currently closed ground→static landing sequence.
// It admits no-property -1/5/6/7 roads only, then calls the room's REAL pure
// preflight for each active actor hypothetically arriving there. Property,
// shop, chance, bank, portal and collision continuations remain excluded.
// Admission is re-evaluated from each plan snapshot, never cached per map.
class RichonlineMineLandingPolicy final {
public:
    using Preflight=std::function<void(const RichonlineLandingContext&)>;
    RichonlineMineLandingPolicy(RichonlineRoadTopology,std::uint32_t mode,
        std::uint8_t local_slot,Preflight);
    RichonlineMineLandingAdmission assess(std::int16_t,const RichonlineCombatSessionView&) const;
    bool supports(std::int16_t,const RichonlineCombatSessionView&) const;
    std::vector<std::int16_t> allowed_positions(const RichonlineCombatSessionView&) const;
private:
    RichonlineRoadTopology topology_;
    std::uint32_t mode_;
    std::uint8_t local_slot_;
    Preflight preflight_;
};
}
