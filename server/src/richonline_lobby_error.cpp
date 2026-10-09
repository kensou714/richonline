#include "richonline_lobby_error.hpp"

namespace richnet {
Frame richonline_lobby_failure(std::uint32_t request_type, std::int32_t reason, View context) {
    if (!context.empty() && context.back() != 0)
        throw CodecError("richonline_error_context_not_nul_terminated");
    Bytes payload;
    append_le(payload, request_type, 4);
    append_le(payload, static_cast<std::uint32_t>(reason), 4);
    if (context.empty()) payload.push_back(0);
    else payload.insert(payload.end(), context.begin(), context.end());
    return {0xffffffffU, std::move(payload)};
}
}
