#pragma once

// KPD 解码与数值选项：当前新版也复用此模块；保留解码大小限制和既有资源格式。

#include "codec.hpp"

#include <filesystem>
#include <string_view>

namespace richnet {
Bytes decode_original_kpd(View data, std::size_t decoded_limit = 4U * 1024U * 1024U);
Bytes load_original_kpd(const std::filesystem::path& path, std::size_t decoded_limit = 4U * 1024U * 1024U);
std::int32_t parse_original_exchange_ratio(std::string_view text);
std::int32_t load_original_exchange_ratio(const std::filesystem::path& path);
std::int32_t parse_original_price_base(std::string_view text);
std::int32_t load_original_price_base(const std::filesystem::path& path);
}
