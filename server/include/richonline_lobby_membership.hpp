#pragma once

#include "codec.hpp"

namespace richnet {

// NEW870F60/871070 sends one literal zero, not an empty leave-channel frame.
void decode_richonline_leave_channel8(const Frame& request);

struct RichonlineRoomTeam9 { std::uint32_t team; };
RichonlineRoomTeam9 decode_richonline_room_team9(const Frame& request);

struct RichonlineRoomKick27 {
    std::uint32_t target_actor, room;
    // Preserve the complete slot: bytes after its first NUL are client padding.
    // The reason can start with control bytes 01 01 or 5C 01, not only text.
    std::array<std::uint8_t,32> reason_slot;
    View reason() const noexcept;
};
RichonlineRoomKick27 decode_richonline_room_kick27(const Frame& request);

Frame encode_richonline_left_channel16();
Frame encode_richonline_room_team17(std::uint32_t actor,std::uint32_t team);
// Every identity is explicit. The request's first DWORD repeats its target and
// must never be trusted as the authenticated kicking actor.
Frame encode_richonline_room_kicked27(std::uint32_t room_owner,std::uint32_t kicking_actor,
    std::uint32_t room,std::uint32_t target_actor,View reason);

} // namespace richnet
