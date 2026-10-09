#pragma once

#include "codec.hpp"
#include <array>
#include <filesystem>
#include <string_view>

namespace richnet {
using RichonlineLevelThresholds=std::array<std::uint32_t,21>;
RichonlineLevelThresholds parse_richonline_level_thresholds(std::string_view decoded);
RichonlineLevelThresholds load_richonline_level_thresholds(const std::filesystem::path& client_root);
}
