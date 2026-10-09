#pragma once

// 大厅物品与装备快照：库存、32 个装备槽及测试 RP 证发放结果。

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace richnet {
struct LobbyInventory {
    std::vector<std::uint32_t> items;
    std::array<std::uint32_t,32> equipment{};
};
struct RpCertificateGrant {
    bool granted{};
    bool renewed{};
    std::size_t equipped{};
    std::size_t conflicts{};
};
struct LobbyEquipmentChange {
    std::int64_t role_id;
    std::uint32_t slot;
    std::uint32_t expected_item;
    std::uint32_t item;
};
}
