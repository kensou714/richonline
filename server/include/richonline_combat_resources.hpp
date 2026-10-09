#pragma once
#include "richonline_combat.hpp"
#include "richonline_boss_stage.hpp"
#include <map>

namespace richnet {
struct RichonlineEquipmentCombatTerms {
    std::int32_t flat_attack=0,attack_percentage=0,flat_defense=0,defense_percentage=0;
    bool operator==(const RichonlineEquipmentCombatTerms&) const = default;
};
class RichonlineCombatModifierResources final {
public:
    static RichonlineCombatModifierResources parse(std::string_view bwb,std::string_view props);
    static RichonlineCombatModifierResources load(const std::filesystem::path& client_root);
    // Only an ACTIVE building buff supplies a level. Ownership alone does not
    // activate the timed Zhong/Chang effect. nullopt is the verified neutral state.
    float attack_building(std::optional<std::uint8_t> active_level) const;
    float defense_building(std::optional<std::uint8_t> active_level) const;
    // Exact actor+144 array: 32 encoded words, low12 bits identify Prop; only
    // records with att_desc participate, as NEW 7F3C70/7FAF80 require.
    RichonlineEquipmentCombatTerms equipment(const std::array<std::uint32_t,32>& words,
        std::uint32_t current_cash) const;
    static std::array<std::uint32_t,32> boss_equipment(const RichonlineBossStage& stage);
private:
    struct Conditional { std::int32_t value=0,threshold=0; char condition=0; };
    std::array<float,8> attack_building_{},defense_building_{};
    std::map<std::uint16_t,std::array<Conditional,4>> equipment_;
    std::uint16_t maximum_prop_=0;
};
// NEW7D9100 initializes all5x5000 limits to-1 (unlimited). Repeated Grant.kpd
// PROP rows overwrite prop/rule/num, matching7D91D0. Missing Grant.kpd leaves
// those constructor defaults, as the startup ignores the load failure.
class RichonlinePropUseLimits final {
public:
    static RichonlinePropUseLimits parse(std::string_view grant);
    static RichonlinePropUseLimits load(const std::filesystem::path& client_root);
    std::int32_t limit(std::uint32_t mode,std::uint16_t prop) const;
    bool allows(std::uint32_t mode,std::uint16_t prop,std::uint16_t previous_uses) const;
private:
    std::map<std::pair<std::uint32_t,std::uint16_t>,std::int32_t> limits_;
};
// Bank0 is the current shared inventory authority. The NEW first matching
// hand slot is consumed; map eligibility is NEW800A50's CARD+membership gate,
// including weight0 rows. This planner stores no independent usage counter.
std::optional<RichonlineBossCards::PreparedConsumption> prepare_richonline_safety_helmet(
    const RichonlineChanceInventory&,std::uint16_t previous_uses,std::uint32_t mode,
    const RichonlinePropUseLimits&,bool prop_and_map_eligible);
}
