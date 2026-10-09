#pragma once

#include <optional>
#include <string>

namespace richnet {
struct GameAccount { std::string username; double gold; };
enum class GameChargeStatus { success, invalid_amount, insufficient_funds };
struct GameGoldCharge {
    double amount;
    std::string operation_id;
    std::string reason;
};
struct GameGoldChargeResult {
    GameChargeStatus status;
    bool replayed;
    // Historical account balance at this operation; never write it back on game exit.
    std::optional<double> gold_after;
};
}
