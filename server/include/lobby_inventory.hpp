#pragma once

// 大厅物品与装备快照：库存、32 个装备槽及测试 RP 证发放结果。

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace richnet {
struct LobbyInventory {
    // 按购买实例顺序保存；同一完整键可以出现多次，不能去重或解释为堆叠数量。
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
    // Lua 使用的角色模型/等级快照；事务内复核，避免资格检查后角色被其他入口修改。
    std::optional<std::array<std::uint32_t,2>> expected_role_state{};
};
}
