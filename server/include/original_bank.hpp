#pragma once

#include "lobby.hpp"
#include "storage.hpp"

namespace richnet {
Frame original_business_error(std::uint32_t request_type, std::int32_t error_code);
BankLimits original_bank_limits(View config);
Frame original_bank_response(Storage& storage, const std::string& username, std::uint32_t role_id,
                             const Frame& request, const BankLimits& limits);
}
