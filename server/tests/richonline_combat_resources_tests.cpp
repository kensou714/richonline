#include "richonline_combat_resources.hpp"
#include <cmath>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* why) { if (!value) throw std::runtime_error(why); }
void rejects(auto action) {
    try { action(); } catch (const CodecError&) { return; }
    throw std::runtime_error("missing_resource_rejection");
}
std::string buildings() {
    std::string result;
    for (const auto* section:{"CHANG","ZHONG"}) {
        result+='['; result+=section; result+="]\n";
        for (int level=1;level<=7;++level) result+="level_"+std::to_string(level)+"=5,3,"+std::to_string(level*10)+"\n";
    }
    return result;
}
void synthetic() {
    const auto bwb=buildings();
    const auto props="[PROP]\nindx=1\ntype=AVATAR\natt_desc=enabled\nattackV=25(<10000)\nattackR=2\ndefendV=15(>10000)\ndefendR=3\n"
        "[PROP]\nindx=2\ntype=AVATAR\nattackV=999\n[PROP]\nindx=3\ntype=AVATAR\natt_desc=enabled\nattackR=1\n";
    const auto data=RichonlineCombatModifierResources::parse(bwb,props);
    std::array<std::uint32_t,32> words{}; words[0]=0x1001; words[5]=2; words[31]=3;
    check(data.equipment(words,9999)==RichonlineEquipmentCombatTerms{25,3,0,3},"low_cash_gating_high_word_mask");
    check(data.equipment(words,10000)==RichonlineEquipmentCombatTerms{0,3,0,3},"strict_threshold");
    check(data.equipment(words,10001)==RichonlineEquipmentCombatTerms{0,3,15,3},"high_cash_defense");
    check(std::abs(data.attack_building(7)-1.7F)<0.00001F && std::abs(data.defense_building(7)-0.3F)<0.00001F,
        "building_multiplier_direction");
    check(data.attack_building({})==1.0F && data.defense_building({})==1.0F,"inactive_building_not_neutral");
    rejects([&] { data.attack_building(0); }); rejects([&] { data.defense_building(8); });
    words[0]=4; rejects([&] { data.equipment(words,0); });
    rejects([&] { RichonlineCombatModifierResources::parse(bwb,"[PROP]\nindx=1\natt_desc=x\nattackV=20(=5)\n"); });
    rejects([&] { RichonlineCombatModifierResources::parse(bwb,"[PROP]\nindx=1\n[PROP]\nindx=1\n"); });
    RichonlineBossStage stage{};
    for (std::size_t i=0;i<stage.boss.equipment.size();++i) stage.boss.equipment[i]=static_cast<std::uint32_t>(i+1);
    const auto equipment=RichonlineCombatModifierResources::boss_equipment(stage);
    check(equipment[0]==1 && equipment[5]==6 && equipment[6]==0 && equipment[7]==7 && equipment[12]==12,
        "boss_slot_gap_wrong");
}
void actual(const std::filesystem::path& root) {
    const auto data=RichonlineCombatModifierResources::load(root);
    std::array<std::uint32_t,32> words{}; words[0]=234; words[7]=235;
    check(data.equipment(words,9999)==RichonlineEquipmentCombatTerms{25,2,15,0},"actual_avatar_attributes");
    check(data.equipment(words,10000)==RichonlineEquipmentCombatTerms{0,2,0,0},"actual_avatar_cash_condition");
    check(std::abs(data.attack_building(1)-1.2F)<0.00001F && std::abs(data.defense_building(5)-0.6F)<0.00001F,
        "actual_bwb_levels");
    const auto stage=load_richonline_boss_stage(root,"BS_1_1.emp");
    check(data.equipment(RichonlineCombatModifierResources::boss_equipment(stage),stage.boss.base_cash)==RichonlineEquipmentCombatTerms{},
        "actual_stage_equipment_neutral");
    check(RichonlinePropUseLimits::load(root).limit(3,1076)==-1,"missing_actual_Grant_does_not_use_ctor_default");
}
void limits_and_helmet_are_pure() {
    const auto defaults=RichonlinePropUseLimits::parse({});
    for(std::uint32_t mode=0;mode<=5;++mode)
        check(defaults.limit(mode,1076)==-1 && defaults.allows(mode,1076,65535),"constructor_unlimited_rules");
    const auto rules=RichonlinePropUseLimits::parse(
        "[VERSION]\nICCode=1\n[PROP]\nprop=1076\nrule=CM\nnum=0\n"
        "[PROP]\nprop=1076\nrule=PK\nnum=1\n[PROP]\nprop=1076\nrule=BS\nnum=1\n"
        "[PROP]\nprop=1076\nrule=BS\nnum=2\n[PROP]\nprop=1076\nrule=TC\nnum=-1\n");
    check(rules.limit(0,1076)==0 && rules.limit(1,1076)==1 && rules.limit(3,1076)==2 &&
        rules.limit(2,1076)==-1 && rules.limit(4,1076)==-1 && rules.limit(3,1071)==-1,"per_mode_and_last_record_rules");
    check(!rules.allows(0,1076,0) && rules.allows(1,1076,0) && !rules.allows(1,1076,1) &&
        rules.allows(3,1076,1) && !rules.allows(3,1076,2),"usage_boundaries");
    RichonlineChanceInventory hand{};hand[2]={1076,2};hand[6]={1076,1};
    const auto first=prepare_richonline_safety_helmet(hand,0,3,rules,true);
    check(first && first->source_inventory==hand && first->slot==2 && first->card_id==1076 &&
        first->remaining_inventory[2].count==1 && hand[2].count==2,"helmet_first_slot_one_unit_pure");
    const auto second=prepare_richonline_safety_helmet(first->remaining_inventory,1,3,rules,true);
    check(second && second->slot==2 && second->remaining_inventory[2]==RichonlineChanceCardSlot{} &&
        second->remaining_inventory[6].count==1,"helmet_empty_slot_normalization");
    check(!prepare_richonline_safety_helmet(second->remaining_inventory,2,3,rules,true) &&
        !prepare_richonline_safety_helmet(hand,0,3,rules,false),"limit_or_map_gate_consumed_helmet");
    const auto third=prepare_richonline_safety_helmet(second->remaining_inventory,65535,3,defaults,true);
    check(third && third->slot==6,"later_hand_slot_or_unlimited_wrap_boundary");
    rejects([&] { RichonlinePropUseLimits::parse("[PROP]\nprop=5000\nrule=BS\nnum=1\n"); });
    rejects([&] { RichonlinePropUseLimits::parse("[PROP]\nprop=1076\nrule=BS\nnum=-2\n"); });
    rejects([&] { RichonlinePropUseLimits::parse("[PROP]\nprop=1076\nrule=BS\n"); });
    hand[2].count=0;
    rejects([&] { prepare_richonline_safety_helmet(hand,0,3,rules,true); });
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_path_required"); synthetic(); actual(argv[1]); limits_and_helmet_are_pure();
        std::cout<<"PASS NEW combat building and equipment resources\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
