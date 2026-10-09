#pragma once

#include "codec.hpp"
#include "storage.hpp"

namespace richnet {
struct RichonlineAccountPolicy {
    BankLimits bank;
    double exchange_ratio;
};

// NEW wire100 and wire30 configuration; all amounts use the client's f64 representation.
RichonlineAccountPolicy richonline_account_policy(View bank_config, View completion);

struct RichonlineAccountReply {
    Frame response;
    std::optional<nlohmann::json> updated_role;
    std::string rejection;
};

// Only financial request contexts verified in NEW are accepted here.
Frame richonline_account_error(std::uint32_t request_type, std::int32_t reason);
std::optional<RichonlineAccountReply> richonline_account_request(
    Storage& storage, const std::string& username, std::uint32_t role_id,
    const Frame& request, const RichonlineAccountPolicy& policy);
}
