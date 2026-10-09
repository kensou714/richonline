#pragma once

#include "codec.hpp"
#include <filesystem>
#include <map>
#include <optional>
#include <string>

namespace richnet {
using OriginalSourceFields = std::map<std::string,std::string>;
struct OriginalPropCard {
    std::int16_t id;
    std::optional<bool> enabled, sale_g;
    std::optional<std::int32_t> price_g, fold;
    OriginalSourceFields source_fields;
};
struct OriginalPropCards {
    Bytes decoded;
    std::vector<OriginalPropCard> cards;
};
struct OriginalCombinationSource {
    std::int16_t card;
    std::int32_t count;
    bool operator==(const OriginalCombinationSource&) const = default;
};
struct OriginalCombination {
    std::array<std::optional<OriginalCombinationSource>,8> sources;
    std::int16_t destination;
    std::optional<bool> enabled;
    OriginalSourceFields source_fields;
};
struct OriginalCardCombinations {
    Bytes decoded;
    std::vector<OriginalCombination> items;
};
OriginalPropCards parse_original_prop_cards(Bytes decoded);
OriginalPropCards load_original_prop_cards(const std::filesystem::path& path);
OriginalCardCombinations parse_original_card_combinations(Bytes decoded);
OriginalCardCombinations load_original_card_combinations(const std::filesystem::path& path);
}
