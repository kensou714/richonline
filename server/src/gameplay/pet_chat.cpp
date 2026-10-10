#include "richonline_pet_chat.hpp"

#include <algorithm>

namespace richnet {
Bytes richonline_pet_chat_response(View request, std::uint16_t game,
    std::uint8_t authenticated_actor, bool equipped) {
    if (request.size() != 18 || read_le(request.first(2)) != 66)
        throw CodecError("richonline_pet_chat_request_invalid");
    if (authenticated_actor >= 8)
        throw CodecError("richonline_pet_chat_actor_invalid");
    if (!equipped)
        throw CodecError("richonline_pet_chat_not_equipped");

    // 647B40 copies at most 13 bytes, then NUL. Ignore its uninitialized tail.
    const auto text = request.subspan(2, 14);
    const auto end = std::find(text.begin(), text.end(), std::uint8_t{0});
    if (end == text.end() || end == text.begin())
        throw CodecError("richonline_pet_chat_text_invalid");

    // 6629D0 consumes the prefix and C string, without a fixed-size check.
    // Its strcpy target has 16 bytes; emit only the bounded text and terminator.
    Bytes response;
    response.reserve(19);
    append_le(response, 0x4042, 2);
    append_le(response, game, 2);
    response.push_back(authenticated_actor);
    response.insert(response.end(), text.begin(), end);
    response.push_back(0);
    return response;
}
}
