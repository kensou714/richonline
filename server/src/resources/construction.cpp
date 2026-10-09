#include "richonline_construction_resources.hpp"
#include "richonline_boss_stage.hpp"
#include "original_building_resources.hpp"
#include "original_options.hpp"
#include <algorithm>
#include <charconv>
#include <set>

namespace richnet {
namespace {
constexpr std::size_t text_limit = 4U*1024U*1024U;
constexpr std::array<std::string_view,10> building_keys{"Yan","Pao","Chang","Zhong","Kong","Mi","Ba","Shan","Zhao","Shou"};
constexpr std::array<std::uint8_t,10> audited_caps{5,5,5,5,0,5,0,0,0,0};
std::string_view trim(std::string_view text) {
    const auto begin = text.find_first_not_of(" \t\r");
    return begin == std::string_view::npos ? std::string_view{} : text.substr(begin,text.find_last_not_of(" \t\r")-begin+1);
}
std::string_view required(const OriginalSourceFields& fields, const std::string& key) {
    const auto found = fields.find(key);
    if (found == fields.end()) throw CodecError("richonline_construction_resource_field_missing");
    return found->second;
}
std::int32_t integer(std::string_view text) {
    std::int32_t value = 0;
    const auto parsed = std::from_chars(text.data(),text.data()+text.size(),value);
    if (text.empty() || parsed.ec != std::errc{} || parsed.ptr != text.data()+text.size())
        throw CodecError("richonline_construction_resource_integer_invalid");
    return value;
}
std::array<std::int16_t,10> licences(std::string_view text) {
    if (text.empty() || text.size() > text_limit || text.find('\0') != text.npos)
        throw CodecError("richonline_construction_resource_text_invalid");
    struct Section { std::string_view name; OriginalSourceFields fields; };
    std::vector<Section> sections;
    while (!text.empty()) {
        const auto newline = text.find('\n');
        const auto line = trim(text.substr(0,newline));
        text = newline == text.npos ? std::string_view{} : text.substr(newline+1);
        if (line.empty() || line.starts_with("//") || line.front() == ';' || line.front() == '#') continue;
        if (line.front() == '[') {
            if (line != "[ALL]" && line != "[BUILD]") throw CodecError("richonline_construction_resource_section_invalid");
            if (sections.size() >= 22) throw CodecError("richonline_construction_resource_count_invalid");
            sections.push_back({line,{}});
            continue;
        }
        const auto split = line.find_first_of("=:");
        if (sections.empty() || split == line.npos) throw CodecError("richonline_construction_resource_field_invalid");
        const auto key = trim(line.substr(0,split));
        if (key.empty() || key.size() > 128 ||
            key.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != key.npos ||
            sections.back().fields.size() >= 256)
            throw CodecError("richonline_construction_resource_field_invalid");
        if (!sections.back().fields.emplace(key,trim(line.substr(split+1))).second)
            throw CodecError("richonline_construction_resource_field_duplicate");
    }
    if (sections.size() != 22 || sections.front().name != "[ALL]" ||
        integer(required(sections.front().fields,"num")) != 21)
        throw CodecError("richonline_construction_resource_count_invalid");
    std::set<std::int32_t> indices;
    std::array<std::int16_t,10> result{};
    for (std::size_t i = 1; i < sections.size(); ++i) {
        const auto& section = sections[i];
        if (section.name != "[BUILD]") throw CodecError("richonline_construction_resource_section_invalid");
        const auto index = integer(required(section.fields,"indx"));
        const auto licence = integer(required(section.fields,"licence"));
        if (index < 0 || index > 20 || !indices.insert(index).second)
            throw CodecError("richonline_construction_resource_index_invalid");
        if (index >= 11) {
            if (licence != 498+index) throw CodecError("richonline_construction_resource_licence_changed");
            result[static_cast<std::size_t>(index-11)] = static_cast<std::int16_t>(licence);
        }
    }
    return result;
}
}
RichonlineConstructionResources RichonlineConstructionResources::parse(std::string_view build, std::string_view boss) {
    const auto licence_ids = licences(build);
    const auto policies = parse_original_building_policies(Bytes(boss.begin(),boss.end()));
    const auto found = std::find_if(policies.maps.begin(),policies.maps.end(),[](const auto& map) {
        return map.map_name == "BS_1_1.emp";
    });
    if (found == policies.maps.end() || found->map_index != 11 || found->default_kind != 11 ||
        integer(required(found->source_fields,"bossNum")) != 1)
        throw CodecError("richonline_construction_scenario_changed");
    RichonlineConstructionResources result{*found->default_kind,licence_ids,{},{}};
    for (std::size_t i = 0; i < building_keys.size(); ++i) {
        const auto skill = found->source_fields.find("bossSkill_"+std::string(building_keys[i]));
        const auto skill_value = skill == found->source_fields.end() ? 0 : integer(skill->second);
        result.scenario_caps[i] = found->level_caps[i].value_or(0);
        if (result.scenario_caps[i] != audited_caps[i] || skill_value != audited_caps[i])
            throw CodecError("richonline_construction_scenario_changed");
        result.synthetic_skills[i] = static_cast<std::uint8_t>(skill_value);
    }
    return result;
}
RichonlineConstructionResources RichonlineConstructionResources::load(const std::filesystem::path& client_root) {
    const auto build = load_original_kpd(client_root/"Data"/"Build.kpd",text_limit);
    const auto boss = load_original_kpd(client_root/"Data"/"BossWar.kpd",text_limit);
    return parse({reinterpret_cast<const char*>(build.data()),build.size()},
        {reinterpret_cast<const char*>(boss.data()),boss.size()});
}
RichonlineConstructionResources RichonlineConstructionResources::load(const std::filesystem::path& client_root,
    const RichonlineBossStage& stage) {
    const auto build = load_original_kpd(client_root/"Data"/"Build.kpd",text_limit);
    return {static_cast<std::int8_t>(stage.default_building_kind),
        licences({reinterpret_cast<const char*>(build.data()),build.size()}),
        stage.scenario_caps,stage.boss.building_skills};
}
}
