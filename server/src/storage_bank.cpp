#include "storage_detail.hpp"

#include <cmath>
#include <limits>

namespace richnet {
using namespace storage_detail;

bool valid_bank_limits(const BankLimits& limits) noexcept {
    return std::isfinite(limits.minimum_deposit) && limits.minimum_deposit >= 0 &&
        std::isfinite(limits.minimum_withdrawal) && limits.minimum_withdrawal >= 0 &&
        std::isfinite(limits.capacity) && limits.capacity >= 0 &&
        limits.minimum_deposit <= limits.capacity && limits.minimum_withdrawal <= limits.capacity;
}

BankStatus Storage::transfer_bank(const std::string& username, std::int64_t role_id, const BankTransfer& transfer) {
    const std::lock_guard lock(mutex_);
    if (!valid_bank_limits(transfer.limits)) throw StorageError("bank_limits_invalid");
    Transaction transaction(db_);
    Statement select(db_,"SELECT role_id,username,gold,bank FROM roles WHERE role_id=? AND username=?");
    select.bind(1,role_id); select.bind(2,username);
    if (!select.row()) throw StorageError("bank_role_not_owned");
    const auto role = select.record();
    const double gold = role.at("gold").get<double>();
    const double bank = role.at("bank").get<double>();
    if (!std::isfinite(gold) || !std::isfinite(bank) || gold < 0 || bank < 0)
        throw StorageError("bank_balance_invalid");
    const auto amount = transfer.amount;
    const bool deposit = transfer.direction == BankDirection::deposit;
    const auto minimum = deposit ? transfer.limits.minimum_deposit : transfer.limits.minimum_withdrawal;
    if (!std::isfinite(amount) || amount <= 0 || amount > std::numeric_limits<std::int32_t>::max() || amount < minimum)
        return BankStatus::invalid_amount;
    if (amount > (deposit ? gold : bank)) return BankStatus::insufficient_funds;
    const double next_gold = deposit ? gold - amount : gold + amount;
    const double next_bank = deposit ? bank + amount : bank - amount;
    if (deposit && next_bank > transfer.limits.capacity) return BankStatus::capacity_exceeded;
    // The reply carries one delta applied to both balances; neither side may silently round it away.
    if (!std::isfinite(next_gold) || !std::isfinite(next_bank) ||
        std::abs(next_gold - gold) != amount || std::abs(next_bank - bank) != amount)
        return BankStatus::invalid_amount;
    Statement update(db_,"UPDATE roles SET gold=?,bank=? WHERE role_id=? AND username=?");
    update.bind(1,next_gold); update.bind(2,next_bank); update.bind(3,role_id); update.bind(4,username); update.row();
    for (const auto* field : {"gold","bank"}) {
        Statement audit(db_,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) VALUES(?,?,?,?,?,'native-bank',?,'')");
        audit.bind(1,role_id); audit.bind(2,username); audit.bind(3,field); audit.bind(4,role.at(field).dump());
        audit.bind(5,nlohmann::json(std::string_view(field) == "gold" ? next_gold : next_bank).dump());
        audit.bind(6,deposit ? "deposit" : "withdraw"); audit.row();
    }
    transaction.commit();
    return BankStatus::success;
}
}
