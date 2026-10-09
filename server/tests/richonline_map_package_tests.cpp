#include "richonline_map_package.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool ok,const char* reason) { if (!ok) throw std::runtime_error(reason); }
template<class F> void rejects(F action,std::string_view reason="richonline_map_package_missing") {
    try { action(); } catch (const CodecError& error) { check(std::string_view(error.what())==reason,error.what()); return; }
    throw std::runtime_error("expected_map_package_missing");
}
void run(const std::filesystem::path& root) {
    const auto& ordinary=find_richonline_map_package("BS_1_1.emp",0);
    const auto& special=find_richonline_map_package("V_BS_1_1.emp",2);
    check(&legacy_richonline_map_package()==&ordinary,"legacy_schema_binding_changed");
    check(ordinary.runtime_enabled && !special.runtime_enabled,"partial_package_runtime_gate_wrong");
    check(ordinary.closed_chance && ordinary.closed_chance->playable_reward_cards==std::vector<std::int16_t>{1038,1039,1040,1041} &&
        ordinary.closed_chance->enable_motion_status,"ordinary_closed_chance_policy_changed");
    check(!special.closed_chance,"special_map_inherited_ordinary_chance_policy");
    check(ordinary.closed_npcs && ordinary.closed_npcs->god_pool==std::vector<std::int8_t>{0,1,2,3} &&
        ordinary.closed_npcs->initial_gods==4 && ordinary.closed_npcs->initial_chests==1 &&
        ordinary.closed_npcs->minimum_objects==2 && ordinary.closed_npcs->maximum_objects==5 &&
        ordinary.closed_npcs->refresh_every_rounds==3 && ordinary.closed_npcs->refresh_chests &&
        ordinary.closed_npcs->fortune_cards==std::array<std::int16_t,2>{1038,1039} &&
        ordinary.closed_npcs->max_transfer==1000 && ordinary.closed_npcs->badluck &&
        ordinary.closed_npcs->badluck->lost_card_limit==4 && ordinary.closed_npcs->badluck->selection==
            RichonlineMapBadluckSelection::uniform_inventory_units_without_replacement,"ordinary_closed_npc_policy_changed");
    check(!special.closed_npcs,"special_map_inherited_ordinary_npc_policy");
    auto local_npcs=*ordinary.closed_npcs;
    local_npcs.god_pool.clear(); local_npcs.max_transfer=1;
    check(ordinary.closed_npcs->god_pool.size()==4 && ordinary.closed_npcs->max_transfer==1000,
        "session_policy_mutated_map_npcs");
    auto local_chance=*ordinary.closed_chance;
    local_chance.playable_reward_cards.clear(); local_chance.enable_motion_status=false;
    check(ordinary.closed_chance->playable_reward_cards.size()==4 && ordinary.closed_chance->enable_motion_status,
        "session_policy_mutated_map_descriptor");
    check(&ordinary==&find_richonline_map_package("BS_1_1.emp",1),"ordinary_category_alias_changed_package");
    check(ordinary.id=="heibeibei" && ordinary.map_name=="BS_1_1.emp" && !ordinary.special_category && ordinary.chance_event==17 && ordinary.readiness==RichonlineMapReadiness::partial,"ordinary_package_identity_wrong");
    check(special.id=="zhao_linger" && special.map_name=="V_BS_1_1.emp" && special.special_category && special.chance_event==2 && special.readiness==RichonlineMapReadiness::partial,"special_package_identity_wrong");
    const auto ordinary_stage=ordinary.load_stage(root,0);
    const auto special_stage=special.load_stage(root,2);
    check(ordinary_stage.map_id==11 && ordinary_stage.map_name==ordinary.map_name && ordinary_stage.category!=2,"ordinary_stage_binding_wrong");
    check(special_stage.map_id==11 && special_stage.map_name==special.map_name && special_stage.category==2 &&
        ordinary_stage.signature!=special_stage.signature && ordinary_stage.human.cash!=special_stage.human.cash &&
        ordinary_stage.scenario_caps!=special_stage.scenario_caps,"same_numeric_id_shared_resources");
    check(ordinary_stage.human.cash==20000 && ordinary_stage.human.tickets==150 && ordinary_stage.boss.base_cash==100000 &&
        ordinary_stage.scenario_caps==std::array<std::uint8_t,10>{5,5,5,5,0,5,0,0,0,0},"ordinary_package_resource_values_wrong");
    check(special_stage.human.cash==12000 && special_stage.human.tickets==350 && special_stage.boss.base_cash==150000 &&
        special_stage.boss.role==-1 && special_stage.boss.equipment[6]==67 &&
        special_stage.scenario_caps==std::array<std::uint8_t,10>{6,6,6,6,0,6,0,0,0,0},"special_package_resource_values_wrong");
    rejects([&] { find_richonline_map_package("BS_1_1.emp",2); });
    rejects([&] { find_richonline_map_package("V_BS_1_1.emp",0); });
    rejects([&] { ordinary.load_stage(root,2); });
    rejects([&] { special.load_stage(root,0); });
    rejects([&] { find_richonline_map_package("V_BS_1_2.emp",2); },"richonline_map_package_resource_missing");
    const RichonlineBossCardPolicy legacy{"legacy.emp",17,1038,{0xa5,0x5a}};
    const auto ordinary_policy=ordinary.configure(legacy);
    check(ordinary_policy.map_name==ordinary.map_name && ordinary_policy.event_id==17 && ordinary_policy.card_id==1038 && ordinary_policy.opaque6_7==legacy.opaque6_7,"ordinary_policy_alias_not_bound");
    const auto special_policy=special.configure(legacy);
    check(special_policy.map_name==special.map_name && special_policy.event_id==2 && special_policy.card_id==1038 && special_policy.opaque6_7==legacy.opaque6_7,"special_policy_alias_not_bound");
    check(ordinary_policy.map_name!=special_policy.map_name && ordinary_policy.event_id!=special_policy.event_id,"map_policy_aliases_collapsed");
    const RichonlineBossCardPolicy changed{"other.emp",22,1010,{0x19,0x91}};
    const auto retained=ordinary.configure(changed);
    const auto isolated=special.configure(changed);
    check(retained.map_name==ordinary.map_name && retained.event_id==22 && retained.card_id==1010 &&
        retained.opaque6_7==changed.opaque6_7,"ordinary_legacy_policy_was_overwritten");
    check(isolated.map_name==special.map_name && isolated.event_id==2 && isolated.card_id==1038 &&
        isolated.opaque6_7==changed.opaque6_7,"special_policy_inherited_other_map_event");
    check(legacy.map_name=="legacy.emp" && legacy.event_id==17 && changed.map_name=="other.emp" && changed.event_id==22,
        "configure_mutated_shared_source_policy");
}
}
int main(int argc,char** argv) {
    try { check(argc==2,"resource_root_required"); run(argv[1]); std::cout<<"PASS immutable NEW map package registry and category isolation\n"; }
    catch(const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
