#include "original_building_resources.hpp"
#include "original_options.hpp"
#include <algorithm>
#include <charconv>
#include <set>

namespace richnet {
namespace {
constexpr std::size_t text_limit = 4U*1024U*1024U;
constexpr std::array<std::string_view,10> building_names{"Yan","Pao","Chang","Zhong","Kong","Mi","Ba","Shan","Zhao","Shou"};
struct Section { std::string name; OriginalSourceFields fields; };
std::string_view trim(std::string_view text) {
    const auto begin = text.find_first_not_of(" \t\r");
    return begin == std::string_view::npos ? std::string_view{} : text.substr(begin,text.find_last_not_of(" \t\r")-begin+1);
}
bool identifier(std::string_view text) {
    return !text.empty() && text.size() <= 128 &&
        text.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") == std::string_view::npos;
}
std::vector<Section> sections(View decoded) {
    if (decoded.empty() || decoded.size() > text_limit || std::find(decoded.begin(),decoded.end(),0) != decoded.end())
        throw CodecError("original_building_text_invalid");
    std::string_view remaining(reinterpret_cast<const char*>(decoded.data()),decoded.size());
    std::vector<Section> result;
    while (!remaining.empty()) {
        const auto newline = remaining.find('\n');
        const auto line = trim(remaining.substr(0,newline));
        remaining = newline == std::string_view::npos ? std::string_view{} : remaining.substr(newline+1);
        if (line.empty() || line.starts_with("//") || line.front() == ';' || line.front() == '#') continue;
        if (line.front() == '[') {
            if (line.back() != ']' || !identifier(line.substr(1,line.size()-2))) throw CodecError("original_building_section_invalid");
            if (result.size() >= 4096 || (!result.empty() && result.back().fields.empty()))
                throw CodecError("original_building_sections_invalid");
            result.push_back({std::string(line.substr(1,line.size()-2)),{}}); continue;
        }
        const auto split = line.find_first_of("=:");
        if (result.empty() || split == std::string_view::npos) throw CodecError("original_building_field_invalid");
        const auto key = trim(line.substr(0,split));
        if (!identifier(key) || result.back().fields.size() >= 1024) throw CodecError("original_building_field_invalid");
        if (!result.back().fields.emplace(key,trim(line.substr(split+1))).second) throw CodecError("original_building_field_duplicate");
    }
    if (result.empty() || result.back().fields.empty()) throw CodecError("original_building_sections_invalid");
    return result;
}
std::string_view required(const OriginalSourceFields& fields, const std::string& key) {
    const auto value = fields.find(key);
    if (value == fields.end()) throw CodecError("original_building_field_missing");
    return value->second;
}
std::int32_t integer(std::string_view text, std::int32_t maximum) {
    if (text.empty() || text.find_first_not_of("0123456789") != std::string_view::npos)
        throw CodecError("original_building_integer_invalid");
    std::int32_t value = 0;
    const auto parsed = std::from_chars(text.data(),text.data()+text.size(),value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data()+text.size() || value > maximum)
        throw CodecError("original_building_integer_range");
    return value;
}
std::int8_t kind(std::string_view name) {
    const auto found = std::find(building_names.begin(),building_names.end(),name);
    if (found == building_names.end()) throw CodecError("original_building_kind_invalid");
    return static_cast<std::int8_t>(11+std::distance(building_names.begin(),found));
}
}
OriginalBuildingPolicies parse_original_building_policies(Bytes decoded) {
    auto raw = sections(decoded);
    OriginalBuildingPolicies result{std::move(decoded),{}};
    std::set<std::int32_t> indices;
    std::set<std::string> names;
    for (auto& section : raw) {
        if (section.name != "MAP") throw CodecError("original_building_section_invalid");
        const auto index = integer(required(section.fields,"mapIndx"),2147483647);
        const std::string name(required(section.fields,"mapName"));
        if (index < 11 || name != "BS_"+std::to_string(index/10)+"_"+std::to_string(index%10)+".emp" ||
            index%10 < 1 || index%10 > 4) throw CodecError("original_building_map_identity_invalid");
        if (!indices.insert(index).second || !names.insert(name).second) throw CodecError("original_building_map_duplicate");
        OriginalBuildingMap map{index,name,std::nullopt,{}, {}};
        const auto default_kind = section.fields.find("defaultBuild");
        if (default_kind != section.fields.end()) map.default_kind = kind(default_kind->second);
        for (std::size_t i = 0; i < building_names.size(); ++i) {
            const auto cap = section.fields.find("maxLev_"+std::string(building_names[i]));
            if (cap != section.fields.end()) map.level_caps[i] = static_cast<std::uint8_t>(integer(cap->second,7));
        }
        map.source_fields = std::move(section.fields);
        result.maps.push_back(std::move(map));
    }
    return result;
}
OriginalBuildingPolicies load_original_building_policies(const std::filesystem::path& path) {
    return parse_original_building_policies(load_original_kpd(path,text_limit));
}
OriginalBuildingPolicy OriginalBuildingPolicies::require(std::string_view name) const {
    const auto found = std::find_if(maps.begin(),maps.end(),[&](const auto& map) { return map.map_name == name; });
    if (found == maps.end()) throw CodecError("original_building_map_missing");
    if (!found->default_kind) throw CodecError("original_building_default_missing");
    return {*found->default_kind,found->level_caps};
}
OriginalResearchResources parse_original_research_resources(Bytes decoded) {
    auto raw = sections(decoded);
    OriginalResearchResources result{std::move(decoded),{},{}};
    for (auto& section : raw)
        if (!result.sections.emplace(section.name,std::move(section.fields)).second)
            throw CodecError("original_research_section_duplicate");
    const auto yan = result.sections.find("YAN");
    if (yan == result.sections.end()) throw CodecError("original_research_section_missing");
    for (std::size_t i = 0; i < result.choices.size(); ++i) {
        const auto value = required(yan->second,"level_"+std::to_string(i+1));
        const auto comma = value.find(',');
        if (comma == std::string_view::npos || value.find(',',comma+1) != std::string_view::npos)
            throw CodecError("original_research_choice_invalid");
        const auto card = integer(trim(value.substr(0,comma)),32767), days = integer(trim(value.substr(comma+1)),127);
        if (card == 0 || days == 0) throw CodecError("original_research_choice_invalid");
        result.choices[i] = {static_cast<std::int16_t>(card),static_cast<std::int8_t>(days)};
    }
    return result;
}
OriginalResearchResources load_original_research_resources(const std::filesystem::path& path) {
    return parse_original_research_resources(load_original_kpd(path,text_limit));
}
}
