#pragma once
#include "richonline_combat.hpp"
#include "richonline_boss_stage.hpp"
#include "richonline_game_payment.hpp"
#include <map>
#include <set>

namespace richnet {
// 保留原错误码，并让大厅能指出具体阻止开局的装备。
class RichonlineEquipmentError final : public CodecError {
public:
    RichonlineEquipmentError(const char* reason,std::size_t slot,std::uint32_t item)
        : CodecError(reason),slot(slot),item(item) {}
    std::size_t slot;
    std::uint32_t item;
};
struct RichonlineEquipmentCombatTerms {
    std::int32_t flat_attack=0,attack_percentage=0,flat_defense=0,defense_percentage=0;
    bool operator==(const RichonlineEquipmentCombatTerms&) const = default;
};
struct RichonlineEquipmentHealingTerms {
    std::int32_t flat=0,per_mille=0;
};
struct RichonlineBuildingBuffRule {
    std::int32_t period=0,duration=0;
    float multiplier=1.0F;
};
class RichonlineCombatModifierResources final {
public:
    static RichonlineCombatModifierResources parse(std::string_view bwb,std::string_view props,
        std::string_view appearance={},std::string_view vehpet={});
    static RichonlineCombatModifierResources load(const std::filesystem::path& client_root);
    // Only an ACTIVE building buff supplies a level. Ownership alone does not
    // activate the timed Zhong/Chang effect. nullopt is the verified neutral state.
    float attack_building(std::optional<std::uint8_t> active_level) const;
    float defense_building(std::optional<std::uint8_t> active_level) const;
    // BwbValue CHANG/ZHONG columns: production period, active duration, modifier.
    // Level is captured when the buff activates, not looked up after an upgrade.
    const RichonlineBuildingBuffRule& building_buff(std::int8_t kind,std::uint8_t level) const;
    // Exact actor+144 array: 32 encoded words, low12 bits identify Prop; only
    // records with att_desc participate, as NEW 7F3C70/7FAF80 require.
    RichonlineEquipmentCombatTerms equipment(const std::array<std::uint32_t,32>& words,
        std::uint32_t current_cash) const;
    RichonlineEquipmentHealingTerms healing(const std::array<std::uint32_t,32>& words,
        std::uint32_t turn_start_cash) const;
    // 开局只放行已接入的槽位效果，按资源 part 校验，保留完整键供客户端外观使用。
    void validate_supported_equipment(const std::array<std::uint32_t,32>& words) const;
    void validate_supported_equipment_slot(std::size_t slot,std::uint32_t word) const;
    // VehPet ITEM indx, not the Prop identifier; equipment word 0 returns nullopt.
    std::optional<std::uint16_t> pet_visual(std::uint32_t word) const;
    RichonlinePaidDiceEquipment paid_dice_equipment(const std::array<std::uint32_t,32>& words) const;
    static std::array<std::uint32_t,32> boss_equipment(const RichonlineBossStage& stage);
private:
    struct Conditional { std::int32_t value=0,threshold=0; char condition=0; };
    std::array<RichonlineBuildingBuffRule,8> attack_building_{},defense_building_{};
    std::array<std::int32_t,6> equipment_values(const std::array<std::uint32_t,32>& words,
        std::uint32_t current_cash) const;
    std::map<std::uint16_t,std::array<Conditional,6>> equipment_;
    struct EquipmentKind { std::string part; bool motorcycle=false,car=false; };
    std::map<std::uint16_t,EquipmentKind> equipment_kinds_;
    std::set<std::uint16_t> move_visuals_,entrance_visuals_;
    std::map<std::uint16_t,std::uint16_t> pet_visuals_;
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
