#pragma once
#include "original_card_resources.hpp"

namespace richnet {
struct OriginalGameValue {
    std::int32_t value;
    OriginalSourceFields source_fields;
};
struct OriginalGameValues {
    Bytes decoded;
    std::map<std::int32_t,OriginalGameValue> entries;
    std::int32_t require(std::int32_t index) const;
};
OriginalGameValues parse_original_game_values(Bytes decoded);
OriginalGameValues load_original_game_values(const std::filesystem::path& path);
}
