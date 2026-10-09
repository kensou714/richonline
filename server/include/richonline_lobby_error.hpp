#pragma once
#include "codec.hpp"

namespace richnet {
// NEW client error consumer reads request id, signed result and NUL terminated context.
// Context is deliberately empty when no verified server text exists.
Frame richonline_lobby_failure(std::uint32_t request_type, std::int32_t reason, View context = {});
}
