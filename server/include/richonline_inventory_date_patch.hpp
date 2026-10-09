#pragma once
#include "codec.hpp"
#include <string>

namespace richnet {
inline constexpr std::string_view richonline_date_original_sha256="CB35F69F3D49C2093897D4EA2CB547A1E38B213F3A8DF0AF52B859F9E661DE77";
std::string richonline_date_image_sha256(View image);
// Hash-bound, read-only transformation. Only3 proven display-epoch immediates
// change. Original executable and all unrelated instructions are preserved.
Bytes richonline_date_compatibility_image(View original);
bool richonline_date_compatibility_image_valid(View patched);
}
