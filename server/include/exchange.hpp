#pragma once

// 点数兑换业务值对象：携带兑换比例、结果状态及可选的更新后角色资料。
#include <cstdint>
#include <optional>
#include <nlohmann/json.hpp>

namespace richnet {
enum class ExchangeStatus { success, invalid_amount, insufficient_funds };
struct GoldExchange {
    double mpoints;
    double ratio;
    GoldExchange(double points, double rate) : mpoints(points), ratio(rate) {}
    GoldExchange(double points, std::int32_t rate) : mpoints(points), ratio(static_cast<double>(rate)) {}
};
struct ExchangeResult {
    ExchangeStatus status;
    std::optional<nlohmann::json> role;
};
}
