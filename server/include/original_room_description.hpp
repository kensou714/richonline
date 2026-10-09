#pragma once

#include "codec.hpp"

#include <filesystem>
#include <string>
#include <unordered_map>

namespace richnet {
class OriginalMapCatalog final {
public:
    static OriginalMapCatalog load(const std::filesystem::path& path);
    std::string validate(View extension) const;
private:
    struct Resource {
        std::string source;
        std::array<std::uint8_t, 16> signature;
    };
    std::unordered_map<std::string, Resource> resources_;
};

struct OriginalGameDescription {
    Bytes wire;
    std::string map_name;
    std::uint32_t max_players;
};

OriginalGameDescription parse_original_game_description(View data, const OriginalMapCatalog& maps);
}
