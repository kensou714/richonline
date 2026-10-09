#pragma once
#include "original_inventory.hpp"

namespace richnet {
struct OriginalTurnStart {
    std::uint16_t instance;
    std::uint8_t current_slot, round_start_slot;
    Bytes opaque_suffix;
};
struct OriginalBossTurnResume {
    std::uint16_t instance;
    Bytes opaque_suffix;
};
struct OriginalInitialCards {
    std::uint16_t instance;
    std::int16_t owner;
    std::array<OriginalCardSlot,4> slots;
    Bytes opaque_suffix;
};
Bytes encode_original_turn_start(const OriginalTurnStart& turn);
Bytes encode_original_boss_turn_resume(const OriginalBossTurnResume& resume);
Bytes encode_original_initial_cards(const OriginalInitialCards& cards);
}
