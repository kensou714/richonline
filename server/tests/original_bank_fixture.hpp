#pragma once

#include <array>
#include <cstdint>

namespace original_bank_test {
inline constexpr std::array<std::uint8_t,32> config{
    0x16,0x16,0x16,0x16,0x16,0x16,0x16,0x16,
    0,0,0,0,0,0,0x59,0x40,
    0,0,0,0,0,0,0x59,0x40,
    0,0,0,0,0,0x40,0x8f,0x40};
inline constexpr auto config_hex = "1616161616161616000000000000594000000000000059400000000000408f40";
}
