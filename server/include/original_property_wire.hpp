#pragma once
#include "codec.hpp"
#include <variant>

namespace richnet {
struct OriginalPropertyPurchase {
    std::uint16_t context;
    std::uint32_t parameter;
    std::int8_t choice;
    std::array<std::uint8_t,3> opaque;
};
struct OriginalClassicUpgrade { std::uint16_t context; std::int8_t choice; std::uint8_t opaque; };
struct OriginalBuildingChoice { std::uint16_t context; std::int8_t choice; std::uint8_t opaque; };
struct OriginalBossUpgrade { std::uint16_t context; std::int8_t choice; std::uint8_t opaque; };
struct OriginalResearchSelection { std::uint16_t context; std::int8_t choice; std::uint8_t opaque; };
using OriginalPropertyRequest = std::variant<OriginalPropertyPurchase,OriginalClassicUpgrade,
    OriginalBuildingChoice,OriginalBossUpgrade,OriginalResearchSelection>;
OriginalPropertyRequest parse_original_property_request(View plain);
Bytes encode_original_property_result(std::uint16_t instance, const OriginalPropertyRequest& decision);
}
