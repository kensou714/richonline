#include "storage_detail.hpp"
#include <cmath>
#include <limits>

namespace richnet {
using namespace storage_detail;
ExchangeResult Storage::exchange_gold(const std::string& username, std::int64_t role_id, const GoldExchange& exchange) {
    const std::lock_guard lock(mutex_);
    if (!std::isfinite(exchange.ratio) || exchange.ratio <= 0 ||
        (profile_ == ClientProfile::original && (exchange.ratio < 1 ||
            std::trunc(exchange.ratio) != exchange.ratio)))
        throw StorageError("exchange_ratio_invalid");
    Transaction transaction(db_);
    Statement select(db_,"SELECT * FROM roles WHERE role_id=? AND username=?");
    select.bind(1,role_id); select.bind(2,username);
    if (!select.row()) throw StorageError("exchange_role_not_owned");
    auto role = select.record();
    const double coins = role.at("coins").get<double>();
    const double gold = role.at("gold").get<double>();
    if (!std::isfinite(coins) || !std::isfinite(gold) || coins < 0 || gold < 0)
        throw StorageError("exchange_balance_invalid");
    const double amount = exchange.mpoints;
    if (!std::isfinite(amount) || amount < 1 || std::trunc(amount) != amount ||
        amount > std::numeric_limits<std::int32_t>::max() / exchange.ratio)
        return {ExchangeStatus::invalid_amount,std::nullopt};
    if (amount > coins) return {ExchangeStatus::insufficient_funds,std::nullopt};
    const double gold_delta = amount * exchange.ratio;
    const double next_coins = coins - amount;
    const double next_gold = gold + gold_delta;
    if (!std::isfinite(next_gold) || !std::isfinite(gold_delta) || gold_delta<=0 ||
        gold_delta / exchange.ratio != amount ||
        coins - next_coins != amount || next_gold - gold != gold_delta)
        return {ExchangeStatus::invalid_amount,std::nullopt};
    Statement write(db_,"UPDATE roles SET coins=?,gold=? WHERE role_id=? AND username=?");
    write.bind(1,next_coins); write.bind(2,next_gold); write.bind(3,role_id); write.bind(4,username); write.row();
    for (const auto* field : {"coins","gold"}) {
        const double value = std::string_view(field) == "coins" ? next_coins : next_gold;
        Statement audit(db_,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) VALUES(?,?,?,?,?,'native-exchange',?,'')");
        audit.bind(1,role_id); audit.bind(2,username); audit.bind(3,field); audit.bind(4,role.at(field).dump());
        audit.bind(5,nlohmann::json(value).dump()); audit.bind(6,"M points to gold ratio=" + std::to_string(exchange.ratio)); audit.row();
        role[field] = value;
    }
    transaction.commit();
    return {ExchangeStatus::success,std::move(role)};
}
}
