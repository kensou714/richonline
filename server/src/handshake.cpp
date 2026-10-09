#include "codec.hpp"

#include <bit>
#include <limits>

namespace richnet {
namespace {
std::int32_t multiply_remainder(std::int32_t left, std::int32_t right, std::int32_t modulus) {
    const auto product = static_cast<std::uint64_t>(std::bit_cast<std::uint32_t>(left))
        * std::bit_cast<std::uint32_t>(right);
    const auto low = static_cast<std::uint32_t>(product);
    const auto dividend = std::bit_cast<std::int32_t>(low);
    if (modulus == 0) throw CodecError("modpow_division_by_zero");
    if (dividend == std::numeric_limits<std::int32_t>::min() && modulus == -1)
        throw CodecError("modpow_division_overflow");
    return dividend % modulus;
}
}

std::int32_t modpow_signed32(std::int32_t base, std::int32_t exponent, std::int32_t modulus) {
    if (exponent <= 0) throw CodecError("exponent_must_be_positive");
    if (modulus <= 0) throw CodecError("modulus_must_be_positive");
    std::int32_t result = 1;
    auto power = base;
    auto remaining = exponent;
    while (remaining != 0) {
        if ((remaining & 1) != 0) result = multiply_remainder(result, power, modulus);
        remaining >>= 1;
        power = multiply_remainder(power, power, modulus);
    }
    return result;
}
}
