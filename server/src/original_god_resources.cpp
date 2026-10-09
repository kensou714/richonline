#include "original_god_resources.hpp"
#include "original_options.hpp"
#include <algorithm>
#include <charconv>
#include <set>

namespace richnet {
namespace {
std::string_view trim(std::string_view text) {
    const auto first = text.find_first_not_of(" \t\r");
    return first == std::string_view::npos ? std::string_view{} : text.substr(first,text.find_last_not_of(" \t\r")-first+1);
}
std::int32_t integer(std::string_view text) {
    text = trim(text);
    std::int32_t value = 0;
    const auto result = std::from_chars(text.data(),text.data()+text.size(),value);
    if (text.empty() || result.ec != std::errc{} || result.ptr != text.data()+text.size())
        throw CodecError("original_god_resource_integer_invalid");
    return value;
}
std::string_view required(const OriginalSourceFields& fields, const std::string& name) {
    const auto found = fields.find(name);
    if (found == fields.end()) throw CodecError("original_god_resource_field_missing");
    return found->second;
}
template<std::size_t N> std::array<std::int32_t,N> row(std::string_view text) {
    std::array<std::int32_t,N> result;
    for (std::size_t i = 0; i < N; ++i) {
        const auto comma = text.find(',');
        if ((i+1 == N) != (comma == std::string_view::npos)) throw CodecError("original_pyramid_resource_arity_invalid");
        result[i] = integer(text.substr(0,comma));
        if (comma != std::string_view::npos) text.remove_prefix(comma+1);
    }
    return result;
}
}
OriginalNpcResources parse_original_npc_resources(Bytes decoded) {
    if (decoded.empty() || decoded.size() > 4U*1024U*1024U || std::find(decoded.begin(),decoded.end(),0) != decoded.end())
        throw CodecError("original_npc_text_invalid");
    std::string_view text(reinterpret_cast<const char*>(decoded.data()),decoded.size());
    std::vector<OriginalSourceFields> records;
    while (!text.empty()) {
        const auto end = text.find('\n'); const auto line = trim(text.substr(0,end));
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end+1);
        if (line.empty() || line.starts_with("//") || line.front() == ';' || line.front() == '#') continue;
        if (line.front() == '[') {
            if (line != "[NPC]" || records.size() >= 4096) throw CodecError("original_npc_section_invalid");
            records.emplace_back(); continue;
        }
        const auto split = line.find('=');
        if (records.empty() || split == std::string_view::npos) throw CodecError("original_npc_field_invalid");
        const auto key = trim(line.substr(0,split));
        if (key.empty() || key.size() > 128 || records.back().size() >= 256) throw CodecError("original_npc_field_invalid");
        if (!records.back().emplace(key,trim(line.substr(split+1))).second) throw CodecError("original_npc_field_duplicate");
    }
    if (records.empty()) throw CodecError("original_npc_records_missing");
    OriginalNpcResources result{std::move(decoded),{}};
    std::set<std::int16_t> ids;
    for (auto& fields : records) {
        const auto id = integer(required(fields,"indx"));
        if (id < 0 || id > 32767 || !ids.insert(static_cast<std::int16_t>(id)).second) throw CodecError("original_npc_id_invalid");
        std::optional<std::int8_t> affix;
        const auto found = fields.find("affix");
        if (found != fields.end()) {
            const auto days = integer(found->second);
            if (days < -128 || days > 127) throw CodecError("original_npc_affix_invalid");
            affix = static_cast<std::int8_t>(days);
        }
        result.records.push_back({static_cast<std::int16_t>(id),affix,std::move(fields)});
    }
    return result;
}
OriginalNpcResources load_original_npc_resources(const std::filesystem::path& path) {
    return parse_original_npc_resources(load_original_kpd(path));
}
OriginalGodRules original_god_rules(const OriginalNpcResources& npcs,
    const OriginalResearchResources& buildings, const OriginalGameValues& values) {
    OriginalGodRules result{};
    for (std::size_t kind = 0; kind < result.affix.size(); ++kind) {
        const auto found = std::find_if(npcs.records.begin(),npcs.records.end(),[kind](const auto& npc) { return npc.id == static_cast<std::int16_t>(kind); });
        if (found == npcs.records.end() || !found->affix || *found->affix <= 0) throw CodecError("original_god_affix_missing_or_invalid");
        result.affix[kind] = *found->affix;
    }
    const auto maximum = values.require(37);
    if (maximum < 1 || maximum > 127) throw CodecError("original_god_maximum_days_invalid");
    result.maximum_days = static_cast<std::int8_t>(maximum);
    const auto mi = buildings.sections.find("MI");
    if (mi == buildings.sections.end()) throw CodecError("original_pyramid_section_missing");
    for (std::size_t i = 0; i < result.pyramid.size(); ++i) {
        const auto prefix = "level_"+std::to_string(i+1);
        const auto summon = row<2>(required(mi->second,prefix+"_zao"));
        const auto harmful = row<4>(required(mi->second,prefix+"_hai"));
        const auto beneficial = row<4>(required(mi->second,prefix+"_yi"));
        for (const auto kind : summon) if (kind < -1 || kind > 7) throw CodecError("original_pyramid_summon_invalid");
        result.pyramid[i] = {static_cast<std::int8_t>(summon[0]),static_cast<std::int8_t>(summon[1]),
            harmful[0],harmful[1],harmful[2],harmful[3],beneficial[0],beneficial[1],beneficial[2],beneficial[3]};
    }
    return result;
}
}
