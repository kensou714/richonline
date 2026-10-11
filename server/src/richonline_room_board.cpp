#include "richonline_room_board.hpp"

#include <algorithm>
#include <limits>
#include <set>

namespace richnet {
std::vector<RichonlineRoomBoardRecipient> build_richonline_room_boards(
    const RichonlineRoomSnapshot& room, RichonlineBoardInit header,
    RichonlineBoardSnapshot snapshot_header,
    std::span<const RichonlineRoomBoardPlayer> players,
    std::span<const RichonlineRoomBoardSynthetic> synthetic) {
    if (room.participants.empty() || room.participants.size() > 4 ||
        players.size() != room.participants.size() || synthetic.size() > 8 - players.size())
        throw CodecError("richonline_room_board_membership_invalid");
    if (!header.participants.empty() || !snapshot_header.slots.empty() ||
        header.game_server_id != snapshot_header.game_server_id)
        throw CodecError("richonline_room_board_header_invalid");
    auto peers = room.participants;
    std::sort(peers.begin(), peers.end(), [](const auto& left, const auto& right) {
        return left.slot < right.slot;
    });
    std::set<std::uint64_t> connections;
    std::set<std::uint32_t> actors, slots;
    for (const auto& peer : peers) {
        if (!peer.ready || !peer.connection || !peer.actor || peer.slot > 3 ||
            peer.actor > static_cast<std::uint32_t>(std::numeric_limits<std::int16_t>::max()) ||
            !connections.insert(peer.connection).second || !actors.insert(peer.actor).second ||
            !slots.insert(peer.slot).second)
            throw CodecError("richonline_room_board_membership_invalid");
        const auto count = std::count_if(players.begin(), players.end(), [&](const auto& player) {
            return player.connection == peer.connection;
        });
        const auto player = std::find_if(players.begin(), players.end(), [&](const auto& entry) {
            return entry.connection == peer.connection;
        });
        if (count != 1 || player->participant.lobby_identity != static_cast<std::int16_t>(peer.actor))
            throw CodecError("richonline_room_board_profile_mismatch");
        if (std::any_of(player->participant.building_skill_caps.begin(),
                        player->participant.building_skill_caps.end(), [](auto cap) { return cap < 0 || cap > 7; }))
            throw CodecError("richonline_room_board_skill_caps_invalid");
        header.participants.push_back(player->participant);
        snapshot_header.slots.push_back(player->balances);
    }
    if (!actors.contains(room.owner)) throw CodecError("richonline_room_board_owner_missing");
    for (const auto& entry : synthetic) {
        if (entry.participant.lobby_identity != -1)
            throw CodecError("richonline_room_board_synthetic_identity_invalid");
        header.participants.push_back(entry.participant);
        snapshot_header.slots.push_back(entry.balances);
    }
    for (const auto& balance : snapshot_header.slots) {
        constexpr auto maximum = static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
        if (balance.cash > maximum || balance.deposit > maximum || balance.tickets > maximum)
            throw CodecError("richonline_room_board_balance_invalid");
    }
    static_cast<void>(encode_richonline_board_snapshot(snapshot_header));
    std::vector<RichonlineRoomBoardRecipient> result;
    result.reserve(peers.size());
    for (std::size_t index = 0; index < peers.size(); ++index) {
        header.local_slot = static_cast<std::uint8_t>(index);
        static_cast<void>(encode_richonline_board_init(header));
        result.push_back({peers[index].connection, header, snapshot_header});
    }
    return result;
}
}
