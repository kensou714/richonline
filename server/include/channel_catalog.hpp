#pragma once

// 频道目录：业务字段与 80 字节线协议记录并存，编码时需保留未确认字段。

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace richnet {
struct ChannelCatalogEntry {
    std::uint32_t key;
    std::string name_utf8;
    std::uint32_t room_capacity;
    std::uint32_t player_capacity;
    std::uint32_t lobby_type;
    std::uint32_t status;
    double min_gold;
    double max_gold;
    std::uint32_t min_level;
    std::uint32_t max_level;
    std::array<std::uint8_t, 80> wire_record;
};
using ChannelCatalog = std::vector<ChannelCatalogEntry>;
}
