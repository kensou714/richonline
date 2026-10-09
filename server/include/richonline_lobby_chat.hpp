#pragma once

#include "richonline_room_directory.hpp"
#include <span>
#include <string>

namespace richnet {
struct RichonlineChatPeer {
    std::uint64_t connection;
    std::uint32_t actor;
    std::uint32_t channel;
    std::optional<std::uint32_t> room;
};
struct RichonlineChatResult {
    std::vector<RichonlineRoomDispatch> deliveries;
    std::string rejection;
};
// NEW wire15 only. Peers must be the authenticated, channel-admitted snapshot.
RichonlineChatResult richonline_lobby_chat(std::uint64_t connection,
    const Frame& request, std::span<const RichonlineChatPeer> peers);
}
