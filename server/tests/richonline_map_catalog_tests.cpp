#include "richonline_map_package.hpp"
#include "original_options.hpp"

#include <algorithm>
#include <iostream>
#include <set>

namespace {
using namespace richnet;
void check(bool value,std::string_view reason) {
    if (!value) throw std::runtime_error(std::string(reason));
}
template<class F> void rejects(F action,std::string_view reason) {
    try { action(); } catch (const CodecError& error) { check(error.what()==reason,error.what()); return; }
    throw std::runtime_error("expected_catalog_rejection");
}
void run(const std::filesystem::path& root) {
    const auto catalog=richonline_map_packages();
    check(catalog.size()==13,"resource_catalog_count_wrong");
    std::set<std::pair<bool,std::string_view>> names;
    const RichonlineBossCardPolicy policy{"BS_1_1.emp",17,1038,{0xa5,0x5a}};
    for (const auto* package:catalog) {
        check(package && names.emplace(package->special_category,package->map_name).second,"catalog_identity_duplicate");
        const bool configured=package->map_name=="BS_1_1.emp" || package->map_name=="BS_1_2.emp" ||
            package->map_name=="BS_1_3.emp" || package->map_name=="BS_1_4.emp" || package->map_name=="V_BS_1_1.emp";
        check(package->closed_chance.has_value()==configured,
            "unopened_map_inherited_closed_chance_policy");
        check(package->closed_npcs.has_value()==configured,
            "unopened_map_inherited_closed_npc_policy");
        check(package->combat.has_value()==configured &&
            package->opening_hand.has_value()==configured,"unopened_map_inherited_combat_or_hand");
        check(package->runtime_enabled==configured,"runtime_gate_wrong");
        const auto category=package->special_category ? 2U : 0U;
        check(&find_richonline_map_package(package->map_name,category)==package,"catalog_lookup_not_exact");
        const auto stage=package->load_stage(root,category);
        const auto map=load_original_emp(root/"Map"/package->map_name);
        check(stage.map_name==package->map_name && stage.category==category &&
            stage.map_id==read_le(View(map.header).subspan(23300,4)) && stage.signature==map.signature,
            "catalog_resource_metadata_mismatch");
        if (!configured) {
            check(!package->runtime_enabled && !package->chance_event && !package->reward_card,
                "unimplemented_map_inherited_runtime_or_reward");
            rejects([&] { package->configure(policy); },"richonline_map_chance_policy_unimplemented");
        }
        if (!package->special_category) {
            for (const auto ordinary_category:{1U,3U,4U,99U,0xffffffffU}) {
                check(&find_richonline_map_package(package->map_name,ordinary_category)==package,"ordinary_category_wrong");
                check(package->load_stage(root,ordinary_category).category==ordinary_category,"category_not_preserved");
            }
        }
        rejects([&] { find_richonline_map_package(package->map_name,package->special_category ? 99U : 2U); },"richonline_map_package_missing");
    }
    for (std::uint32_t chapter=1;chapter<=3;++chapter) {
        for (std::uint32_t level=1;level<=4;++level) {
            const auto name="BS_"+std::to_string(chapter)+"_"+std::to_string(level)+".emp";
            const auto stage=find_richonline_map_package(name,0).load_stage(root,0);
            check(stage.map_id==chapter*10+level,"shipped_stage_id_wrong");
            const auto role=chapter==1 ? 0 : chapter==2 ? 4 : -1;
            const auto suit=chapter==1 ? 31U : chapter==2 ? 47U : 80U;
            check(stage.boss.role==role && stage.boss.equipment[6]==suit,"boss_group_identity_shared");
            check(stage.boss.count==1 && stage.player_count_choices==std::vector<std::uint32_t>{1,2,3,4},
                "shipped_player_or_boss_count_changed");
        }
    }
    const auto& first=find_richonline_map_package("BS_1_1.emp",0);
    check(first.closed_npcs && first.closed_npcs->badluck && first.closed_npcs->badluck->lost_card_limit==4 &&
          first.closed_npcs->badluck->selection==RichonlineMapBadluckSelection::uniform_inventory_units_without_replacement,
          "map_badluck_policy_missing");
    const auto& combat=*first.combat;
    check(combat.attempts==4 && combat.idle_weight==80 && combat.mine_weight==10 && combat.projectile_weight==10 &&
          combat.uniform_projectiles==std::vector<RichonlineMapProjectile>{RichonlineMapProjectile::missile,
              RichonlineMapProjectile::nuclear,RichonlineMapProjectile::safe_nuclear} &&
          combat.targets_within_visibility && combat.allow_self_target && combat.attacks_require_actionable_status &&
          !combat.consume_boss_inventory,"explicit_boss_combat_policy_changed");
    check(first.opening_hand->human==std::vector<RichonlineMapOpeningCard>{{1038,1},{1044,1}} &&
          first.opening_hand->boss.empty(),"opening_hand_user_policy_changed");
    rejects([&] { find_richonline_map_package("V_BS_1_2.emp",2); },"richonline_map_package_resource_missing");
    rejects([&] { load_richonline_boss_stage(root,"V_BS_1_2.emp",2); },"richonline_stage_map_resource_missing");
    rejects([&] { find_richonline_map_package("BS_4_1.emp",0); },"richonline_map_package_missing");
    check(load_richonline_boss_stage(root,"BS_1_1.emp",0xffffffffU).category==0xffffffffU,"selector_bits_truncated");

    const auto bytes=load_original_kpd(root/"Data/BossWar.kpd");
    std::string text(bytes.begin(),bytes.end());
    std::erase_if(text,[](char c) { return c==' ' || c=='\t' || c=='\r'; });
    const auto at=text.find("mapIndx=11");
    check(at!=text.npos,"fixture_map_index_missing");
    text.replace(at,10,"mapIndx=81");
    auto map=load_original_emp(root/"Map/BS_1_1.emp");
    rejects([&] { parse_richonline_boss_stage(text,"BS_1_1.emp",map); },"richonline_stage_map_metadata_mismatch");
    map.header[23300]=81;
    check(parse_richonline_boss_stage(text,"BS_1_1.emp",map).map_id==81,"map_id_inferred_from_filename");
    rejects([&] { parse_richonline_boss_stage(std::string(2*1024*1024+1,'x'),"BS_1_1.emp",map); },"richonline_stage_table_too_large");
    rejects([&] { parse_richonline_boss_stage(std::string(4097,'x'),"BS_1_1.emp",map); },"richonline_stage_line_too_large");
}
}
int main(int argc,char** argv) {
    try { check(argc==2,"NEW_resource_root_required"); run(argv[1]); std::cout<<"PASS NEW 13-map resource catalog and metadata boundaries\n"; }
    catch(const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
