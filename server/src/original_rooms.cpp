#include "original_rooms.hpp"
#include "original_game_host.hpp"

#include <algorithm>
#include <utility>

namespace richnet {
namespace {
void put(Bytes& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i=0; i<4; ++i) bytes.at(offset+i) = static_cast<std::uint8_t>(value >> (8*i));
}
Bytes words(std::initializer_list<std::uint32_t> values) {
    Bytes bytes;
    for (const auto value : values) append_le(bytes,value,4);
    return bytes;
}
}
OriginalRoomDirectory::OriginalRoomDirectory(std::shared_ptr<const OriginalMapCatalog> maps,
    std::uint32_t capacity, LobbyLogSink log, std::shared_ptr<OriginalGameHost> host, std::uint32_t channel)
    : maps_(std::move(maps)),capacity_(capacity),log_(std::move(log)),host_(std::move(host)),channel_(channel) {
    if (host_ && channel_ == 0) throw CodecError("original_room_channel_required");
}

std::optional<std::uint32_t> OriginalRoomDirectory::game_for(std::uint32_t user) const {
    for (const auto& [id, game] : games_)
        if (game.slots.contains(user)) return id;
    return std::nullopt;
}
bool OriginalRoomDirectory::ready(std::uint32_t user) const {
    const auto id = game_for(user);
    return id && games_.at(*id).ready_users.contains(user);
}
Bytes OriginalRoomDirectory::profile(std::uint32_t user) const {
    return apply_membership(user,participants_.at(user).source());
}
Bytes OriginalRoomDirectory::apply_membership(std::uint32_t user, Bytes bytes) const {
    if (bytes.size() != 268 || read_le(View(bytes).first(4)) != user)
        throw CodecError("original_room_profile_invalid");
    const auto id = game_for(user);
    put(bytes,12,id.value_or(0xffffffffU));
    if (id) put(bytes,44,games_.at(*id).slots.at(user).team);
    return bytes;
}
Bytes OriginalRoomDirectory::configuration(const Game& game) const {
    auto bytes = game.description.wire;
    put(bytes,60,game.owner);
    put(bytes,64,game.slots.at(game.owner).team);
    put(bytes,32,(read_le(View(bytes).subspan(32,4)) & ~0x800U) | (game.launch ? 0x800U : 0U));
    return bytes;
}
void OriginalRoomDirectory::enqueue(std::uint32_t user, const Frame& frame) {
    auto& participant = participants_.at(user);
    if (participant.overflow) return;
    if (participant.pending.size() >= 4096 || frame.payload.size() > 4*1024*1024-participant.pending_bytes) {
        participant.overflow = true;
        participant.pending.clear();
        participant.pending_bytes = 0;
        return;
    }
    participant.pending.push_back(frame);
    participant.pending_bytes += frame.payload.size();
}
void OriginalRoomDirectory::broadcast(const Frame& frame) {
    for (const auto& [user, participant] : participants_) {
        static_cast<void>(participant);
        enqueue(user,frame);
    }
}
void OriginalRoomDirectory::send_profile(std::uint32_t recipient, std::uint32_t user) {
    auto bytes = profile(user);
    auto& known = participants_.at(recipient).known_users;
    const auto type = known.contains(user) ? 23U : 7U;
    enqueue(recipient,{type,std::move(bytes)});
    known.insert(user);
}
void OriginalRoomDirectory::snapshot(std::uint32_t user, std::uint32_t id, const Game& game) {
    auto bytes = words({id,0});
    const auto config = configuration(game);
    bytes.insert(bytes.end(),config.begin(),config.end());
    enqueue(user,{5,std::move(bytes)});
    for (const auto ready_state : {true,false}) {
        Bytes members(4);
        std::uint32_t count = 0;
        for (std::uint32_t slot=0; slot<game.description.max_players; ++slot) {
            for (const auto& [member, member_slot] : game.slots) {
                if (member_slot.slot == slot && game.ready_users.contains(member) == ready_state) {
                    append_le(members,member,4);
                    ++count;
                }
            }
        }
        put(members,0,count);
        enqueue(user,{ready_state ? 40U : 41U,std::move(members)});
    }
}
void OriginalRoomDirectory::enter(std::uint32_t user, ProfileSource source) {
    refresh_games();
    if (participants_.contains(user)) throw CodecError("original_lobby_role_already_online");
    participants_.emplace(user,Participant{std::move(source),{},0,false,{user}});
    try {
        for (const auto& [id,game] : games_) {
            for (const auto& [member,slot] : game.slots) {
                static_cast<void>(slot);
                send_profile(user,member);
            }
            snapshot(user,id,game);
        }
    } catch (...) { participants_.erase(user); throw; }
}
std::vector<Frame> OriginalRoomDirectory::drain(std::uint32_t user) {
    refresh_games();
    auto& participant = participants_.at(user);
    if (participant.overflow) throw CodecError("original_lobby_outbound_capacity_exceeded");
    participant.pending_bytes = 0;
    return std::exchange(participant.pending,{});
}
void OriginalRoomDirectory::leave(std::uint32_t user) {
    const auto id = game_for(user);
    if (!id) return;
    if (games_.at(*id).launch) {
        if (finish_game(*id)) return;
    }
    auto& game = games_.at(*id);
    game.slots.erase(user);
    game.ready_users.erase(user);
    if (game.owner == user) {
        const auto next = std::min_element(game.slots.begin(),game.slots.end(),[](const auto& a,const auto& b) {
            return a.second.slot < b.second.slot;
        });
        game.owner = next == game.slots.end() ? 0xffffffffU : next->first;
    }
    broadcast({14,words({user,*id,game.owner})});
    if (game.slots.empty()) games_.erase(*id);
}
void OriginalRoomDirectory::disconnect(std::uint32_t user) {
    if (!participants_.contains(user)) return;
    participants_.erase(user);
    leave(user);
}
void OriginalRoomDirectory::model_changed(std::uint32_t user, std::uint32_t model) {
    broadcast({18,words({user,model})});
}
}
