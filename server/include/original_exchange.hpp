#pragma once
#include "original_bank.hpp"

namespace richnet {
struct OriginalExchangeResult { Frame response; std::optional<nlohmann::json> role; };
OriginalExchangeResult original_exchange_response(Storage& storage, const std::string& username,
    std::uint32_t role_id, const Frame& request, std::int32_t ratio);
}
