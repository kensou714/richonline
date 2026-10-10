#pragma once

#include "codec.hpp"

namespace richnet {
// request is the complete decoded C2S 66 packet. Identity and equipment must
// come from the authenticated session; the request contains only text.
Bytes richonline_pet_chat_response(View request, std::uint16_t game,
    std::uint8_t authenticated_actor, bool equipped);
}
