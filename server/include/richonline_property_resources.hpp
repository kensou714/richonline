#pragma once

#include "original_map.hpp"
#include <optional>
#include <string_view>

namespace richnet {
// NEW 7DF010 creates property state from every EMP sprite 11/12 record.
// Ownership starts at the client's -1 sentinel, including prebuilt buildings.
struct RichonlineInitialProperty {
    std::int16_t id;
    std::int8_t sprite_type, kind;
    std::uint8_t level;
    std::optional<std::uint8_t> owner;
    std::uint32_t price;
    std::int16_t district;
    std::array<std::optional<std::int16_t>,2> links;
    std::vector<std::int16_t> road_tiles;
    // Preserve remaining source fields without pretending their semantics are
    // gameplay counters. No field in this record supplies an initial owner.
    std::array<std::uint8_t,88> resource_record;
};
struct RichonlinePropertyResources {
    std::uint32_t width, height;
    std::vector<RichonlineInitialProperty> properties;
};

RichonlinePropertyResources richonline_property_resources(const OriginalEmp& emp,
    std::int32_t price_base);
RichonlinePropertyResources load_richonline_property_resources(
    const std::filesystem::path& client_root,std::string_view map_name);
}
