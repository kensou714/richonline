#pragma once

// EMP 资源解析结构：当前新版也复用此模块；original 命名不代表当前开发目标是旧客户端。

#include "original_board.hpp"
#include <filesystem>

namespace richnet {
struct OriginalEmp {
    std::uint32_t version, width, height;
    std::array<std::uint8_t,16> signature;
    Bytes header, payload;
    std::size_t terrain_offset, tile_types_offset, property_offset, tail_offset;
};
struct OriginalRoadCell {
    std::int16_t tile, property_id;
    std::int8_t type;
};
struct OriginalRoadEdge {
    std::int16_t from, to;
    std::uint8_t direction;
    bool operator==(const OriginalRoadEdge&) const = default;
};
struct OriginalMapProperty {
    std::int16_t id;
    std::int8_t owner, sprite_type, kind, level;
    std::int32_t price;
};
struct OriginalCardWeight {
    std::int16_t card;
    std::uint32_t weight;
};
struct OriginalMapResources {
    OriginalEmp emp;
    std::vector<OriginalRoadCell> roads;
    std::vector<OriginalRoadEdge> edges;
    std::vector<OriginalMapProperty> properties;
    OriginalFunds human_funds;
    std::uint32_t scale;
    std::vector<OriginalCardWeight> card_weights;
    std::vector<std::int16_t> pool_a_ids, pool_b_ids;
    std::size_t parsed_tail_bytes;
};
OriginalEmp decode_original_emp(View file);
OriginalEmp load_original_emp(const std::filesystem::path& path);
OriginalMapResources original_map_resources(OriginalEmp emp, std::int32_t price_base);
}
