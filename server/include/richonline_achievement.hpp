#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace richnet {
enum class RichonlineAchievement : std::int32_t { stock = 1, cash_earned = 3, land = 9, double_kill = 13, bomb = 15 };
// Explicit local scoring rule; the original server's formula is not recovered.
inline constexpr const char* richonline_cash_earned_policy = "local-v1:sum-positive-board-cash-plus-deposit-deltas";

struct GameSettlementAchievement {
    RichonlineAchievement category;
    std::uint64_t score;
    std::string policy;
    // Captured under the same ledger lock as score, then frozen for settlement.
    std::optional<std::uint64_t> ledger_revision{};
};
}
