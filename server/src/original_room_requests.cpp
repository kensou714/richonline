#include "original_rooms.hpp"
#include "original_game_host.hpp"

#include <algorithm>
#include <array>

namespace richnet {
namespace {
Bytes words(std::initializer_list<std::uint32_t> values) {
    Bytes bytes;
    for (const auto value : values) append_le(bytes,value,4);
    return bytes;
}
void exact(const Frame& frame, std::size_t size) {
    if (frame.payload.size() != size) throw CodecError("original_room_request_length_invalid");
}
}
void OriginalRoomDirectory::request(std::uint32_t user, const Frame& frame) {
    if (!participants_.contains(user)) throw CodecError("original_room_session_required");
    if (!maps_) throw CodecError("original_room_maps_not_configured");
    refresh_games();
    const auto current = game_for(user);
    const View input(frame.payload);
    switch (frame.wire_type) {
    case 3: {
        if (current) throw CodecError("original_room_already_joined");
        auto description = parse_original_game_description(input,*maps_);
        if (description.wire.size() < 208) throw CodecError("original_room_ui_extension_truncated");
        std::uint32_t id = 0;
        while (id < capacity_ && games_.contains(id)) ++id;
        if (id == capacity_) throw CodecError("original_room_capacity_exhausted");
        auto& game = games_.emplace(id,Game{user,std::move(description),{{user,{0,0}}},{},{}}).first->second;
        auto bytes = words({id,user});
        const auto config = configuration(game);
        bytes.insert(bytes.end(),config.begin(),config.end());
        enqueue(user,{10,std::move(bytes)});
        for (const auto& [observer,participant] : participants_) {
            static_cast<void>(participant);
            if (observer == user) continue;
            send_profile(observer,user);
            snapshot(observer,id,game);
        }
        return;
    }
    case 4: {
        exact(frame,12);
        if (current) throw CodecError("original_room_already_joined");
        const auto id = read_le(input.first(4));
        const auto requested_team = read_le(input.subspan(4,4));
        if ((requested_team > 3 && requested_team != 0xffffffffU) || read_le(input.subspan(8,4)) != 1)
            throw CodecError("original_room_join_variant_unsupported");
        if (!games_.contains(id)) throw CodecError("original_room_missing");
        auto& game = games_.at(id);
        if (game.launch) throw CodecError("original_room_game_in_progress");
        std::set<std::uint32_t> occupied;
        std::array<std::uint32_t,4> teams{};
        for (const auto& [member, position] : game.slots) {
            static_cast<void>(member);
            occupied.insert(position.slot);
            ++teams.at(position.team);
        }
        std::uint32_t slot = 0;
        while (occupied.contains(slot)) ++slot;
        if (slot >= game.description.max_players) throw CodecError("original_room_full");
        const auto team = requested_team == 0xffffffffU ?
            static_cast<std::uint32_t>(std::min_element(teams.begin(),teams.end())-teams.begin()) : requested_team;
        game.slots.emplace(user,Game::Member{slot,team});
        for (const auto& [observer,participant] : participants_) {
            static_cast<void>(participant);
            if (observer != user) send_profile(observer,user);
        }
        broadcast({12,words({user,id,team,1})});
        return;
    }
    case 23: {
        if (input.size() < 4) throw CodecError("original_room_request_length_invalid");
        const auto id = read_le(input.first(4));
        if (!current || *current != id || games_.at(id).owner != user)
            throw CodecError("original_room_owner_required");
        auto description = parse_original_game_description(input.subspan(4),*maps_);
        if (description.wire.size() < 208) throw CodecError("original_room_ui_extension_truncated");
        auto& game = games_.at(id);
        if (game.launch) throw CodecError("original_room_game_in_progress");
        for (const auto& [member,position] : game.slots) {
            static_cast<void>(member);
            if (position.slot >= description.max_players) throw CodecError("original_room_occupied_slot_excluded");
        }
        for (const auto member : game.ready_users) broadcast({96,words({member,id})});
        game.ready_users.clear();
        game.description = std::move(description);
        auto bytes = words({id});
        const auto config = configuration(game);
        bytes.insert(bytes.end(),config.begin(),config.end());
        broadcast({26,std::move(bytes)});
        return;
    }
    case 9: {
        if (!current) throw CodecError("original_room_membership_required");
        auto& member = games_.at(*current).slots.at(user);
        if (input.size() != 4 || read_le(input) > 3 || ready(user)) {
            if (log_) log_("original_room_request_rejected request_type=9 reason=invalid_team_or_ready");
            enqueue(user,{17,words({user,member.team})});
            return;
        }
        member.team = read_le(input);
        broadcast({17,words({user,member.team})});
        return;
    }
    case 6:
        exact(frame,4);
        if (read_le(input) != 0) throw CodecError("original_room_leave_variant_unsupported");
        leave(user);
        return;
    case 5:
    case 60: {
        exact(frame,0);
        if (!current) throw CodecError("original_room_membership_required");
        auto& game = games_.at(*current);
        if (game.launch) {
            if (frame.wire_type == 5) return;
            if (host_->status(*game.launch).admitted) throw CodecError("original_room_game_in_progress");
            finish_game(*current);
            return;
        }
        if (frame.wire_type == 60) {
            if (game.ready_users.erase(user) != 0) broadcast({96,words({user,*current})});
        } else if (game.ready_users.contains(user)) {
            return;
        } else {
            game.ready_users.insert(user);
            broadcast({13,words({user,*current})});
            if (game.ready_users.size() == game.slots.size()) start_game(*current,user);
        }
        return;
    }
    default: throw CodecError("original_room_request_unsupported");
    }
}
}
