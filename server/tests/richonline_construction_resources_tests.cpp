#include "richonline_construction_resources.hpp"
#include "richonline_boss_stage.hpp"
#include <iostream>
#include <string>

namespace {
using namespace richnet;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
std::string build_fixture() {
    std::string text = "[ALL]\nnum=21\n";
    for (int kind = 0; kind <= 20; ++kind)
        text += "[BUILD]\nindx="+std::to_string(kind)+"\nname=fixture\nlicence="+
            std::to_string(kind >= 11 ? 498+kind : -1)+"\n";
    return text;
}
std::string boss_fixture() {
    return "[MAP]\nmapIndx=11\nmapName=BS_1_1.emp\nbossNum=1\ndefaultBuild=Yan\n"
        "maxLev_Yan=5\nmaxLev_Pao=5\nmaxLev_Chang=5\nmaxLev_Zhong=5\nmaxLev_Mi=5\n"
        "bossSkill_Yan=5\nbossSkill_Pao=5\nbossSkill_Chang=5\nbossSkill_Zhong=5\nbossSkill_Mi=5\n";
}
void check_policy(const RichonlineConstructionResources& result) {
    check(result.default_kind == 11,"default_wrong");
    check(result.licence_ids == std::array<std::int16_t,10>{509,510,511,512,513,514,515,516,517,518},"licences_wrong");
    const std::array<std::uint8_t,10> caps{5,5,5,5,0,5,0,0,0,0};
    check(result.scenario_caps == caps && result.synthetic_skills == caps,"caps_or_skills_wrong");
}
template<class Action> void rejects(Action action) {
    try { action(); } catch (const CodecError&) { return; }
    throw std::runtime_error("changed_resource_accepted");
}
std::string changed(std::string text, std::string_view before, std::string_view after) {
    const auto offset = text.find(before); check(offset != text.npos,"fixture_target_missing");
    text.replace(offset,before.size(),after); return text;
}
void audited_rules_parse_and_omitted_caps_stay_zero() {
    check_policy(RichonlineConstructionResources::parse(build_fixture(),boss_fixture()));
}
void changed_build_rules_fail_closed() {
    for (const auto& build : {
        changed(build_fixture(),"num=21","num=22"),
        changed(build_fixture(),"licence=512","licence=999"),
        changed(build_fixture(),"indx=14","indx=13"),
        changed(build_fixture(),"licence=509","licence=509\nlicence=509"),
        changed(build_fixture(),"indx=20","indx=21"),
        changed(build_fixture(),"licence=509","licence=garbage")})
        rejects([&] { RichonlineConstructionResources::parse(build,boss_fixture()); });
}
void changed_scenario_rules_fail_closed() {
    for (const auto& boss : {
        changed(boss_fixture(),"defaultBuild=Yan","defaultBuild=Zhong"),
        changed(boss_fixture(),"maxLev_Yan=5","maxLev_Yan=7"),
        changed(boss_fixture(),"bossSkill_Mi=5","bossSkill_Mi=7"),
        changed(boss_fixture(),"mapIndx=11","mapIndx=12"),
        changed(boss_fixture(),"bossNum=1","bossNum=2"),
        changed(boss_fixture(),"mapName=BS_1_1.emp","mapName=BS_1_2.emp"),
        boss_fixture()+"maxLev_Kong=1\n",boss_fixture()+boss_fixture(),
        changed(boss_fixture(),"maxLev_Mi=5\n","")})
        rejects([&] { RichonlineConstructionResources::parse(build_fixture(),boss); });
}
void malformed_text_fails_closed() {
    rejects([] { RichonlineConstructionResources::parse("",boss_fixture()); });
    rejects([] { RichonlineConstructionResources::parse(build_fixture(),""); });
    const auto embedded = build_fixture()+std::string(1,'\0');
    rejects([&] { RichonlineConstructionResources::parse(embedded,boss_fixture()); });
    rejects([] { RichonlineConstructionResources::parse(build_fixture()+"[UNKNOWN]\nx=1\n",boss_fixture()); });
}
void selected_stage_controls_construction(const std::filesystem::path& root) {
    const auto ordinary=load_richonline_boss_stage(root,"BS_1_1.emp");
    check_policy(RichonlineConstructionResources::load(root,ordinary));
    auto stage=load_richonline_boss_stage(root,"V_BS_1_1.emp",2);
    const auto special=RichonlineConstructionResources::load(root,stage);
    const std::array<std::uint8_t,10> caps{6,6,6,6,0,6,0,0,0,0};
    check(special.default_kind==11 && special.scenario_caps==caps && special.synthetic_skills==caps,
        "special_stage_lost_level_six");
    check(special.licence_ids==std::array<std::int16_t,10>{509,510,511,512,513,514,515,516,517,518},
        "stage_loader_lost_build_licences");
    stage.default_building_kind=14;
    stage.scenario_caps[3]=4;
    stage.boss.building_skills[3]=2;
    const auto changed=RichonlineConstructionResources::load(root,stage);
    check(changed.default_kind==14 && changed.scenario_caps[3]==4 && changed.synthetic_skills[3]==2,
        "construction_values_did_not_follow_selected_stage");
}
}
int main(int argc, char** argv) {
    try { audited_rules_parse_and_omitted_caps_stay_zero(); changed_build_rules_fail_closed();
        changed_scenario_rules_fail_closed(); malformed_text_fails_closed();
        if (argc == 2) {
            const std::filesystem::path root(argv[1]);
            check_policy(RichonlineConstructionResources::load(root));
            selected_stage_controls_construction(root);
        }
        else if (argc != 1) throw std::runtime_error("expected_optional_client_root");
        std::cout << "richonline_construction_resources_tests passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
