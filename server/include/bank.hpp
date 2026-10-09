#pragma once

// 银行业务值对象：统一存取方向、最低金额、容量限制与失败状态。

namespace richnet {
enum class BankDirection { deposit, withdraw };
enum class BankStatus { success, invalid_amount, insufficient_funds, capacity_exceeded };
struct BankLimits {
    double minimum_deposit;
    double minimum_withdrawal;
    double capacity;
};
struct BankTransfer {
    BankDirection direction;
    double amount;
    BankLimits limits;
};
bool valid_bank_limits(const BankLimits& limits) noexcept;
}
