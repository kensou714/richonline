#pragma once
#include "codec.hpp"

namespace richnet {
struct OriginalWealthChoice {
    std::uint16_t context;
    std::uint8_t action, opaque;
};
OriginalWealthChoice parse_original_wealth_choice(View plain);
Bytes encode_original_wealth_result(std::uint16_t instance, std::int16_t amount, bool bankruptcy_wait);
Bytes encode_original_blessing_result(std::uint16_t instance, std::array<std::int16_t,2> cards);
Bytes encode_original_misfortune_result(std::uint16_t instance, std::array<std::int8_t,4> slots);
Bytes encode_original_npc_spawn(std::uint16_t instance, std::int16_t tile, std::uint8_t kind);
}
