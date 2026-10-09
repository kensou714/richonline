#pragma once

// 建筑资源解析：读取地图等级限制与研究选项；供现有资源读取链复用，不代表旧客户端开发目标。
#include "original_card_resources.hpp"

namespace richnet {
struct OriginalBuildingPolicy {
    std::int8_t default_kind;
    std::array<std::optional<std::uint8_t>,10> level_caps;
};
struct OriginalBuildingMap {
    std::int32_t map_index;
    std::string map_name;
    std::optional<std::int8_t> default_kind;
    std::array<std::optional<std::uint8_t>,10> level_caps;
    OriginalSourceFields source_fields;
};
struct OriginalBuildingPolicies {
    Bytes decoded;
    std::vector<OriginalBuildingMap> maps;
    OriginalBuildingPolicy require(std::string_view map_name) const;
};
struct OriginalResearchChoice {
    std::int16_t card;
    std::int8_t days;
    bool operator==(const OriginalResearchChoice&) const = default;
};
struct OriginalResearchResources {
    Bytes decoded;
    std::array<OriginalResearchChoice,7> choices;
    std::map<std::string,OriginalSourceFields> sections;
};
OriginalBuildingPolicies parse_original_building_policies(Bytes decoded);
OriginalBuildingPolicies load_original_building_policies(const std::filesystem::path& path);
OriginalResearchResources parse_original_research_resources(Bytes decoded);
OriginalResearchResources load_original_research_resources(const std::filesystem::path& path);
}
