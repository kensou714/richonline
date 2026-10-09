#pragma once
#include "original_building_resources.hpp"
#include "original_game_values.hpp"
#include "original_god_state.hpp"

namespace richnet {
struct OriginalNpcRecord {
    std::int16_t id;
    std::optional<std::int8_t> affix;
    OriginalSourceFields source_fields;
};
struct OriginalNpcResources {
    Bytes decoded;
    std::vector<OriginalNpcRecord> records;
};
OriginalNpcResources parse_original_npc_resources(Bytes decoded);
OriginalNpcResources load_original_npc_resources(const std::filesystem::path& path);
std::array<OriginalPyramidRule,7> original_pyramid_rules(const OriginalResearchResources& buildings);
OriginalGodRules original_god_rules(const OriginalNpcResources& npcs,
    const OriginalResearchResources& buildings, const OriginalGameValues& values);
}
