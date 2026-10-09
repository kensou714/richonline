#include "original_god_resources.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool ok, const char* reason) { if (!ok) throw std::runtime_error(reason); }
template<class F> void rejects(F action, std::string_view reason) {
    try { action(); } catch (const CodecError& error) {
        if (error.what() != reason) throw std::runtime_error(std::string("expected ")+std::string(reason)+", got "+error.what()); return;
    }
    throw std::runtime_error("expected rejection missing");
}
Bytes bytes(std::string_view text) { return Bytes(text.begin(),text.end()); }
void actual_resources() {
    constexpr std::u8string_view path = RICHONLINE_LEGACY_RESOURCE_ROOT;
    const auto root = std::filesystem::path(std::u8string(path.begin(),path.end()));
    const auto npcs = load_original_npc_resources(root/"Data"/"Npc.kpd");
    auto buildings = load_original_research_resources(root/"Data"/"BwbValue.kpd");
    const auto values = load_original_game_values(root/"Data"/"GValue.kpd");
    const auto rules = original_god_rules(npcs,buildings,values);
    check(rules.affix == std::array<std::int8_t,8>{5,5,5,5,5,3,5,3} && rules.maximum_days == 5,"actual NPC affix and GValue37");
    check(rules.pyramid[0].friendly_harmful_days == 1 && rules.pyramid[3].friendly_harmful_days == -1,"pyramid removal rules");
    check(rules.pyramid[4].enemy_summon == 6 && rules.pyramid[4].friendly_summon == 4 &&
        rules.pyramid[5].enemy_summon == 2 && rules.pyramid[5].friendly_summon == 3 &&
        rules.pyramid[6].enemy_summon == 1 && rules.pyramid[6].friendly_summon == 0,"all seven levels decoded without five-level restriction");
    check(rules.pyramid[6].enemy_harmful_effect == 20 && rules.pyramid[6].friendly_beneficial_effect == 20 &&
        rules.pyramid[6].enemy_beneficial_days == -1,"level7 effect and weakening are separate fields");
    buildings.sections.at("MI").at("level_1_hai") = "0,0,1";
    rejects([&] { original_god_rules(npcs,buildings,values); },"original_pyramid_resource_arity_invalid");
    auto missing = npcs; missing.records.erase(missing.records.begin());
    rejects([&] { original_god_rules(missing,buildings,values); },"original_god_affix_missing_or_invalid");
    std::cout << "Original NPC records=" << npcs.records.size() << ", pyramid levels=" << rules.pyramid.size() << '\n';
}
void parser_boundaries() {
    const auto raw = bytes("[NPC]\nindx=0\naffix=5\nname=\xd2\xa3\n[NPC]\nindx=9\nanew=0\n");
    const auto parsed = parse_original_npc_resources(raw);
    check(parsed.decoded == raw && parsed.records[0].source_fields.at("name") == "\xd2\xa3" && !parsed.records[1].affix,
        "GBK and absent affix are retained explicitly");
    rejects([] { parse_original_npc_resources(bytes("[NPC]\nindx=0\nindx=1\n")); },"original_npc_field_duplicate");
    rejects([] { parse_original_npc_resources(bytes("[NPC]\nindx=0\n[NPC]\nindx=0\n")); },"original_npc_id_invalid");
    rejects([] { parse_original_npc_resources(bytes("[NPC]\nindx=0\naffix=128\n")); },"original_npc_affix_invalid");
    rejects([] { parse_original_npc_resources(bytes("[NPC]\naffix=5\n")); },"original_god_resource_field_missing");
    rejects([] { parse_original_npc_resources(bytes("[OTHER]\nindx=0\n")); },"original_npc_section_invalid");
}
}
int main() {
    try { actual_resources(); parser_boundaries(); std::cout << "PASS original NPC and pyramid resource rules.\n"; return 0; }
    catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
