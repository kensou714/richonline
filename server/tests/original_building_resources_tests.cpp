#include "original_building_resources.hpp"
#include <functional>
#include <iostream>

namespace {
using namespace richnet;
Bytes bytes(std::string_view text) { return Bytes(text.begin(),text.end()); }
void check(bool value, std::string_view message) {
    if (!value) throw std::runtime_error(std::string(message));
}
void rejects(const std::function<void()>& action, std::string_view code) {
    try { action(); } catch (const CodecError& error) {
        check(error.what() == code,std::string("unexpected rejection: ")+error.what()); return;
    }
    throw std::runtime_error("expected rejection missing");
}
std::string complete_map() {
    return "[MAP]\nmapIndx=11\nmapName=BS_1_1.emp\ndefaultBuild=Mi\n"
        "maxLev_Yan=1\nmaxLev_Pao=2\nmaxLev_Chang=3\nmaxLev_Zhong=4\nmaxLev_Kong=0\n"
        "maxLev_Mi=5\nmaxLev_Ba=6\nmaxLev_Shan=7\nmaxLev_Zhao=0\nmaxLev_Shou=3\nopaque=\xd2\xa3\n";
}
std::string research() {
    return "[YAN]\nlevel_1=1001,1\nlevel_2=1002,2\nlevel_3=1003,3\nlevel_4=1004,4\n"
        "level_5=1005,5\nlevel_6=1006,6\nlevel_7=1007,7\n[OTHER]\nopaque=\xbf\xd8\n";
}
void test_building_fields() {
    const auto raw = bytes(complete_map());
    const auto parsed = parse_original_building_policies(raw);
    check(parsed.decoded == raw && parsed.maps.size() == 1 && parsed.maps[0].source_fields.at("opaque") == "\xd2\xa3",
        "map metadata and GBK bytes preserved");
    const auto policy = parsed.require("BS_1_1.emp");
    check(policy.default_kind == 16 && policy.level_caps == std::array<std::optional<std::uint8_t>,10>{1,2,3,4,0,5,6,7,0,3},
        "map caps must retain all ten kind positions");
    const std::array<std::string_view,10> names{"Yan","Pao","Chang","Zhong","Kong","Mi","Ba","Shan","Zhao","Shou"};
    for (std::size_t i = 0; i < names.size(); ++i) {
        auto raw_kind = complete_map(); raw_kind.replace(raw_kind.find("defaultBuild=Mi"),15,"defaultBuild="+std::string(names[i])+"\n");
        check(parse_original_building_policies(bytes(raw_kind)).require("BS_1_1.emp").default_kind == static_cast<std::int8_t>(11+i),
            "building token mapping11..20");
    }
    const auto missing = parse_original_building_policies(bytes("[MAP]\nmapIndx=11\nmapName=BS_1_1.emp\n"));
    check(!missing.maps[0].default_kind && !missing.maps[0].level_caps[0],"absent fields retain unknown status");
    rejects([&] { missing.require("BS_1_1.emp"); },"original_building_default_missing");
    const auto partial = parse_original_building_policies(bytes("[MAP]\nmapIndx=11\nmapName=BS_1_1.emp\ndefaultBuild=Yan\nmaxLev_Yan=5\n"));
    const auto sparse = partial.require("BS_1_1.emp");
    check(sparse.level_caps[0] == 5 && !sparse.level_caps[1],"known kinds remain usable without inventing omitted caps");
    rejects([&] { parsed.require("BS_1_4.emp"); },"original_building_map_missing");
}
void test_building_rejections() {
    rejects([&] { parse_original_building_policies({}); },"original_building_text_invalid");
    rejects([&] { parse_original_building_policies(bytes("[MAP]\n")); },"original_building_sections_invalid");
    rejects([&] { parse_original_building_policies(bytes("[MAP]\nmapIndx=11")); },"original_building_field_missing");
    rejects([&] { parse_original_building_policies(bytes(complete_map()+complete_map())); },"original_building_map_duplicate");
    rejects([&] { parse_original_building_policies(bytes(complete_map()+"maxLev_Yan=2\n")); },"original_building_field_duplicate");
    for (const auto name : {"BS_1_2.emp","../BS_1_1.emp","bs_1_1.emp"})
        rejects([&] { parse_original_building_policies(bytes("[MAP]\nmapIndx=11\nmapName="+std::string(name))); },"original_building_map_identity_invalid");
    for (const auto value : {"8","255","9999999999999999"})
        rejects([&] { parse_original_building_policies(bytes("[MAP]\nmapIndx=11\nmapName=BS_1_1.emp\nmaxLev_Yan="+std::string(value))); },"original_building_integer_range");
    for (const auto value : {"-1","1x","true"})
        rejects([&] { parse_original_building_policies(bytes("[MAP]\nmapIndx=11\nmapName=BS_1_1.emp\nmaxLev_Yan="+std::string(value))); },"original_building_integer_invalid");
    rejects([&] { parse_original_building_policies(bytes("[MAP]\nmapIndx=11\nmapName=BS_1_1.emp\ndefaultBuild=yan")); },"original_building_kind_invalid");
    rejects([&] { parse_original_building_policies(Bytes(4U*1024U*1024U+1U,' ')); },"original_building_text_invalid");
}
void test_research_fields_and_rejections() {
    const auto raw = bytes(research());
    const auto parsed = parse_original_research_resources(raw);
    check(parsed.decoded == raw && parsed.sections.at("OTHER").at("opaque") == "\xbf\xd8","all sections and raw GBK survive");
    for (std::size_t i = 0; i < 7; ++i)
        check(parsed.choices[i] == OriginalResearchChoice{static_cast<std::int16_t>(1001+i),static_cast<std::int8_t>(1+i)},
            "all seven choice entries decode by level key");
    rejects([&] { parse_original_research_resources(bytes("[OTHER]\nfield=1")); },"original_research_section_missing");
    rejects([&] { parse_original_research_resources(bytes("[YAN]\nlevel_1=1,1")); },"original_building_field_missing");
    rejects([&] { parse_original_research_resources(bytes(research()+"[YAN]\nlevel_1=1,1")); },"original_research_section_duplicate");
    for (const auto pair : {"1","1,1,1","0,1","1,0"}) {
        auto invalid = research(); invalid.replace(invalid.find("1001,1"),6,pair);
        rejects([&] { parse_original_research_resources(bytes(invalid)); },"original_research_choice_invalid");
    }
    for (const auto pair : {"32768,1","1,128"}) {
        auto invalid = research(); invalid.replace(invalid.find("1001,1"),6,pair);
        rejects([&] { parse_original_research_resources(bytes(invalid)); },"original_building_integer_range");
    }
}
void test_actual_resources() {
    constexpr std::string_view source_path = __FILE__;
    const auto root = std::filesystem::path(std::u8string(source_path.begin(),source_path.end())).parent_path().parent_path().parent_path();
    const auto policies = load_original_building_policies(root / "Data" / "BossWar.kpd");
    check(policies.maps.size() == 8,"original BossWar oracle has eight MAP records");
    for (std::size_t i = 0; i < policies.maps.size(); ++i) {
        const auto& map = policies.maps[i];
        const auto chapter = i/4+1, stage = i%4+1;
        check(map.map_name == "BS_"+std::to_string(chapter)+"_"+std::to_string(stage)+".emp" &&
            map.map_index == static_cast<std::int32_t>(chapter*10+stage) && map.default_kind == 11,"original map identity/default Yan");
        for (std::size_t kind = 0; kind < 10; ++kind) {
            if (kind < 4 || kind == 5) check(map.level_caps[kind] == static_cast<std::uint8_t>(chapter+4),"original chapter1/2 caps5/6");
            else check(!map.level_caps[kind],"missing source caps remain distinguishable");
        }
    }
    const auto yan = load_original_research_resources(root / "Data" / "BwbValue.kpd");
    const std::array<OriginalResearchChoice,7> expected{{{1044,1},{1038,1},{1047,2},{1181,2},{1063,3},{1070,4},{500,5}}};
    check(yan.choices == expected,"original BwbValue independent oracle seven card/day pairs");
    check(yan.sections.at("PAO").at("level_1") == "5,1046,3,0" && yan.sections.at("MI").at("level_5_zao") == "6,  4",
        "untyped miracle-building sections preserved");
}
}
int main() {
    try {
        test_building_fields(); test_building_rejections(); test_research_fields_and_rejections(); test_actual_resources();
        std::cout << "PASS original BossWar building policies and BwbValue research resources.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
