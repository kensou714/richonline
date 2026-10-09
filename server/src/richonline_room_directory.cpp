#include "richonline_room_directory.hpp"
#include "richonline_lobby_membership.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <utility>

namespace richnet {
namespace {
Frame scalars(std::uint32_t wire, std::initializer_list<std::uint32_t> fields) {
    Bytes payload;
    for (const auto field : fields) append_le(payload, field, 4);
    return {wire, std::move(payload)};
}
void append(std::vector<RichonlineRoomDispatch>& destination, std::vector<RichonlineRoomDispatch> source) {
    destination.insert(destination.end(), std::make_move_iterator(source.begin()), std::make_move_iterator(source.end()));
}
void put(RichonlineRoomDescription& description, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) description.record[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
}
bool same_client_metadata(const RichonlineRoomDescription& stored, const RichonlineRoomDescription& incoming,
                          std::uint32_t owner, std::uint32_t slot) {
    auto expected = stored;
    const auto received_flags = stored.field(32);
    if ((received_flags & 0x100U) == 0) put(expected, 48, 0xffffffffU);
    if ((received_flags & 0x200U) == 0) { put(expected, 52, 0); put(expected, 56, 0); }
    const auto f64_bits = static_cast<std::uint64_t>(expected.field(52)) |
                          (static_cast<std::uint64_t>(expected.field(56)) << 32);
    const auto flags = (expected.field(48) != 0xffffffffU ? 0x100U : 0U) |
                       (std::bit_cast<double>(f64_bits) != 0.0 ? 0x200U : 0U) |
                       (!stored.extension.empty() ? 0x40U : 0U);
    put(expected, 32, flags); put(expected, 60, owner); put(expected, 64, slot);
    put(expected, 72, stored.field(40));
    put(expected, 108, 0); put(expected, 112, 0); put(expected, 116, 0);
    for (const std::size_t offset : {std::size_t{0}, std::size_t{76}}) {
        const auto begin = expected.record.begin() + static_cast<std::ptrdiff_t>(offset);
        const auto end = std::find(begin, begin + 32, std::uint8_t{0});
        if (!std::equal(begin, end + 1, incoming.record.begin() + static_cast<std::ptrdiff_t>(offset))) return false;
    }
    return std::equal(expected.record.begin() + 32, expected.record.begin() + 76, incoming.record.begin() + 32) &&
           std::equal(expected.record.begin() + 108, expected.record.begin() + 120, incoming.record.begin() + 108);
}
bool settlement_field(std::size_t offset) {
    return (offset >= 24 && offset < 36) || (offset >= 52 && offset < 56) ||
           (offset >= 80 && offset < 96) || (offset >= 104 && offset < 112);
}
bool finite_double(View payload, std::size_t offset) {
    const auto bits = static_cast<std::uint64_t>(read_le(payload.subspan(offset, 4))) |
                      (static_cast<std::uint64_t>(read_le(payload.subspan(offset + 4, 4))) << 32);
    return std::isfinite(std::bit_cast<double>(bits));
}
}

RichonlineRoomDirectory::RichonlineRoomDirectory(RichonlineRoomPolicy policy, RichonlineRoomLog log)
    : log_(std::move(log)), policy_(policy) {
    if (policy.room_capacity == 0 || policy.room_capacity > 32767)
        throw CodecError("richonline_room_policy_invalid");
}
std::size_t RichonlineRoomDirectory::peer_count(std::uint32_t room_key) const {
    const auto found = rooms_.find(room_key);
    return found == rooms_.end() ? 0 : found->second.peers.size();
}
void RichonlineRoomDirectory::log(const std::string& message) const { if (log_) log_(message); }
void RichonlineRoomDirectory::profile_location(std::uint64_t connection, std::uint32_t key, std::uint32_t team) {
    auto& payload = observers_.at(connection).profile.payload;
    for (std::size_t i = 0; i < 4; ++i) {
        payload[12 + i] = static_cast<std::uint8_t>(key >> (i * 8));
        payload[44 + i] = static_cast<std::uint8_t>(team >> (i * 8));
    }
}
RichonlineRoomDirectory::Room& RichonlineRoomDirectory::room_for_peer(std::uint64_t connection) {
    for (auto& item : rooms_) if (item.second.peers.contains(connection)) return item.second;
    throw CodecError("richonline_room_peer_not_in_room");
}
std::optional<std::uint32_t> RichonlineRoomDirectory::room_key(std::uint64_t connection) const {
    for (const auto& item : rooms_) if (item.second.peers.contains(connection)) return item.first;
    return {};
}
Frame RichonlineRoomDirectory::current_profile(std::uint64_t connection, std::uint32_t actor) const {
    const auto found = observers_.find(connection);
    if (found == observers_.end() || found->second.actor != actor)
        throw CodecError("richonline_room_actor_not_registered");
    return found->second.profile;
}
void RichonlineRoomDirectory::refresh_profile(std::uint64_t connection, std::uint32_t actor,
                                             const Frame& expected_current, const Frame& update) {
    const auto found = observers_.find(connection);
    if (found == observers_.end() || found->second.actor != actor)
        throw CodecError("richonline_room_actor_not_registered");
    const auto& current = found->second.profile;
    if (expected_current.wire_type != 7 || expected_current.payload.size() != 272 ||
        read_le(View(expected_current.payload).first(4)) != actor)
        throw CodecError("richonline_room_expected_profile_invalid");
    if (expected_current.wire_type != current.wire_type || expected_current.payload != current.payload)
        throw CodecError("richonline_room_profile_stale");
    if (update.wire_type != 19 || update.payload.size() != 144 ||
        read_le(View(update.payload).first(4)) != actor)
        throw CodecError("richonline_room_profile_refresh_invalid");
    if (std::find(update.payload.begin() + 112, update.payload.end(), std::uint8_t{0}) == update.payload.end() ||
        !finite_double(update.payload, 80) || !finite_double(update.payload, 88))
        throw CodecError("richonline_room_profile_refresh_values_invalid");
    for (std::size_t offset = 0; offset < update.payload.size(); ++offset) {
        if (!settlement_field(offset) && update.payload[offset] != current.payload[offset])
            throw CodecError("richonline_room_profile_refresh_field_unproven");
    }
    Frame refreshed = current;
    for (std::size_t offset = 0; offset < update.payload.size(); ++offset) {
        if (settlement_field(offset)) refreshed.payload[offset] = update.payload[offset];
    }
    found->second.profile = std::move(refreshed);
}
std::optional<RichonlineRoomSnapshot> RichonlineRoomDirectory::ready_game(std::uint64_t connection) {
    auto& room = room_for_peer(connection);
    if (room.game_pending || std::any_of(room.peers.begin(), room.peers.end(), [](const auto& item) { return !item.second.ready; })) return {};
    RichonlineRoomSnapshot snapshot{room.key, room.owner, room.description, {}};
    for (const auto& item : room.peers) snapshot.participants.push_back(item.second);
    return snapshot;
}
void RichonlineRoomDirectory::set_game_pending(std::uint64_t connection, bool pending) { room_for_peer(connection).game_pending = pending; }
bool RichonlineRoomDirectory::game_pending(std::uint64_t connection) const {
    const auto key=room_key(connection);
    return key && rooms_.at(*key).game_pending;
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::game_finished(std::uint32_t room_key) {
    const auto found = rooms_.find(room_key);
    if (found == rooms_.end() || !found->second.game_pending) return {};
    found->second.game_pending = false;
    std::vector<RichonlineRoomDispatch> result;
    for (auto& item : found->second.peers) {
        item.second.ready = false;
        append(result, broadcast(scalars(96, {item.second.actor, room_key})));
    }
    // NEW 87FD30 wire58 reads the room DWORD and callback6AC070 clears
    // its game state while preserving the room and its participants.
    append(result,broadcast(scalars(58,{room_key})));
    return result;
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::broadcast(const Frame& frame) const {
    std::vector<RichonlineRoomDispatch> result;
    for (const auto& item : observers_) result.push_back({item.first, frame});
    return result;
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::select_character(
    std::uint64_t connection, std::uint32_t character, const std::function<void()>& persist) {
    const auto observer = observers_.find(connection);
    if (observer == observers_.end()) throw CodecError("richonline_room_actor_not_registered");
    if (character > 8 || !persist) throw CodecError("richonline_character_selection_invalid");
    auto& room = room_for_peer(connection);
    if (room.game_pending || room.peers.at(connection).ready)
        throw CodecError("richonline_character_selection_while_ready");
    auto response = broadcast(scalars(18, {observer->second.actor, character}));
    persist();
    auto& profile = observer->second.profile.payload;
    for (std::size_t i = 0; i < 4; ++i) profile[40+i] = static_cast<std::uint8_t>(character >> (i*8));
    log("room_character_selected key=" + std::to_string(room.key));
    return response;
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::enter(std::uint64_t connection, std::uint32_t actor, Frame profile) {
    if (observers_.contains(connection)) throw CodecError("richonline_channel_already_entered");
    if (actor == 0 || std::any_of(observers_.begin(), observers_.end(), [actor](const auto& item) { return item.second.actor == actor; }))
        throw CodecError("richonline_actor_already_online_or_invalid");
    if (profile.wire_type != 7 || profile.payload.size() != 272 || read_le(View(profile.payload).first(4)) != actor)
        throw CodecError("richonline_peer_profile_invalid");
    std::vector<RichonlineRoomDispatch> result;
    for (const auto& [peer, observer] : observers_) {
        result.push_back({connection, observer.profile});
        result.push_back({peer, profile});
    }
    for (const auto& [key, room] : rooms_) {
        result.push_back({connection, richonline_room_record(5, room.description,
            {key, policy_.unknown_prefix, room.owner, room.wire_slot, room.description.field(40)})});
        for (const auto& item : room.peers) {
            const auto& member = item.second;
            result.push_back({connection, scalars(12, {member.actor, key, member.team, 1})});
            if (member.ready) result.push_back({connection, scalars(13, {member.actor, key})});
        }
    }
    observers_.emplace(connection, Observer{actor, std::move(profile)});
    return result;
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::create(std::uint64_t connection, std::uint32_t actor, View payload) {
    auto description = decode_richonline_room_create(payload);
    const auto selected_count = description.field(40);
    const auto mode = description.field(36);
    if (selected_count < 1 || selected_count > 4 || (selected_count == 1 && mode != 2 && mode != 3))
        throw CodecError("richonline_room_selected_player_count_invalid");
    for (const auto& item : rooms_) if (item.second.peers.contains(connection)) throw CodecError("richonline_room_peer_already_joined");
    if (rooms_.size() >= policy_.room_capacity) throw CodecError("richonline_room_capacity_reached");
    std::uint32_t key = next_key_ % policy_.room_capacity;
    while (rooms_.contains(key)) key = (key + 1) % policy_.room_capacity;
    next_key_ = (key + 1) % policy_.room_capacity;
    Room room{key, std::move(description), actor, {},0,false,{}};
    room.peers.emplace(connection, RichonlineRoomPeer{connection, actor, 0, false});
    const auto identity = RichonlineRoomIdentity{key, policy_.unknown_prefix, actor, 0, selected_count};
    std::vector<RichonlineRoomDispatch> result;
    for (const auto& item : observers_)
        result.push_back({item.first, richonline_room_record(10, room.description, identity)});
    rooms_.emplace(key, std::move(room));
    profile_location(connection, key, 0);
    log("room_created key=" + std::to_string(key));
    return result;
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::join(std::uint64_t connection, std::uint32_t actor, View payload) {
    if (payload.size() != 12) throw CodecError("richonline_room_join_length_invalid");
    const auto key = read_le(payload.first(4));
    const auto requested = read_le(payload.subspan(4, 4));
    const auto mode = read_le(payload.subspan(8, 4));
    if (mode != 1) throw CodecError("richonline_room_join_mode_unimplemented");
    for (const auto& item : rooms_) if (item.second.peers.contains(connection)) throw CodecError("richonline_room_peer_already_joined");
    const auto found = rooms_.find(key);
    if (found == rooms_.end()) throw CodecError("richonline_room_not_found");
    if (found->second.game_pending) throw CodecError("richonline_room_game_admission_pending");
    if (found->second.peers.size() >= found->second.description.field(40)) throw CodecError("richonline_room_full");
    if (requested > 3) throw CodecError("richonline_room_join_team_invalid");
    // NEW888070/888290 stores wire12's third DWORD in actor+88 (team).
    // Simulation slots remain unique even when several players share a team.
    std::uint32_t slot=0;
    while(std::any_of(found->second.peers.begin(),found->second.peers.end(),
        [slot](const auto& item){return item.second.slot==slot;})) ++slot;
    auto result=cancel_vote(found->second);
    found->second.peers.emplace(connection, RichonlineRoomPeer{connection, actor, slot, false, requested});
    profile_location(connection, key, requested);
    log("room_peer_joined key=" + std::to_string(key));
    append(result,broadcast(scalars(12, {actor, key, requested, 1})));
    return result;
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::prepare(std::uint64_t connection, View payload, bool ready) {
    if (!payload.empty()) throw CodecError(ready ? "richonline_room_prepare_payload_invalid" : "richonline_room_cancel_payload_invalid");
    auto& room = room_for_peer(connection);
    auto& peer = room.peers.at(connection);
    if (ready && room.game_pending) throw CodecError("richonline_room_game_admission_pending");
    if (peer.ready == ready) throw CodecError("richonline_room_ready_state_unchanged");
    auto result=cancel_vote(room);
    peer.ready = ready;
    log(std::string("room_peer_") + (ready ? "ready" : "unready") + " key=" + std::to_string(room.key));
    append(result,broadcast(scalars(ready ? 13U : 96U, {peer.actor, room.key})));
    return result;
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::remove(std::uint64_t connection) {
    auto& room = room_for_peer(connection);
    const auto key = room.key;
    const auto actor = room.peers.at(connection).actor;
    auto remaining = room.peers;
    remaining.erase(connection);
    const auto new_owner = room.owner == actor && !remaining.empty() ? remaining.begin()->second.actor : room.owner;
    auto result = cancel_vote(room);
    append(result,broadcast(scalars(14, {actor, key, new_owner})));
    room.owner = new_owner;
    room.peers = std::move(remaining);
    profile_location(connection, 0xffffffffU, 0xfffffffeU);
    if (room.peers.empty()) {
        append(result, broadcast(scalars(57, {key})));
        rooms_.erase(key);
    } else append(result, game_finished(key));
    log("room_peer_left key=" + std::to_string(key));
    return result;
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::leave(std::uint64_t connection, View payload) {
    if (payload.size() != 4 || read_le(payload) != 1) throw CodecError("richonline_room_leave_payload_invalid");
    return remove(connection);
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::edit(std::uint64_t connection, std::uint32_t actor, View payload) {
    auto edit = decode_richonline_room_edit(payload);
    auto& room = room_for_peer(connection);
    if (room.game_pending) throw CodecError("richonline_room_game_admission_pending");
    if (room.owner != actor) throw CodecError("richonline_room_edit_not_owner");
    if (edit.tag != room.key) throw CodecError("richonline_room_edit_tag_mismatch");
    if (!same_client_metadata(room.description, edit.description, room.owner, room.wire_slot))
        throw CodecError("richonline_room_metadata_update_unproven");
    Bytes response;
    append_le(response, room.key, 4);
    response.insert(response.end(), edit.description.record.begin(), edit.description.record.end());
    response.insert(response.end(), edit.description.extension.begin(), edit.description.extension.end());
    auto result=cancel_vote(room);
    room.description.extension = std::move(edit.description.extension);
    put(room.description, 120, static_cast<std::uint32_t>(room.description.extension.size()));
    put(room.description, 32, (room.description.field(32) & ~0x40U) | (room.description.extension.empty() ? 0U : 0x40U));
    log("room_extension_updated key=" + std::to_string(room.key));
    append(result,broadcast({26, std::move(response)}));
    return result;
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::receive(std::uint64_t connection, std::uint32_t actor, const Frame& request,
    RichonlineLobbyVote::Time now) {
    const auto observer = observers_.find(connection);
    if (observer == observers_.end() || observer->second.actor != actor) throw CodecError("richonline_room_actor_not_registered");
    switch (request.wire_type) {
    case 39: case 40: return vote_request(connection,request,now);
    case 3: return create(connection, actor, request.payload);
    case 4: return join(connection, actor, request.payload);
    case 5: return prepare(connection, request.payload, true);
    case 6: return leave(connection, request.payload);
    case 9: return select_team(connection, request);
    case 27: return kick(connection, request);
    case 23: return edit(connection, actor, request.payload);
    case 60: return prepare(connection, request.payload, false);
    default: throw CodecError("richonline_room_request_unsupported");
    }
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::select_team(std::uint64_t connection,const Frame& request) {
    const auto team=decode_richonline_room_team9(request).team;
    auto& room=room_for_peer(connection);
    auto& peer=room.peers.at(connection);
    if(room.game_pending||peer.ready) throw CodecError("richonline_room_team_while_ready");
    auto result=broadcast(encode_richonline_room_team17(peer.actor,team));
    peer.team=team;
    profile_location(connection,room.key,team);
    log("room_team_selected key="+std::to_string(room.key)+" team="+std::to_string(team));
    return result;
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::kick(std::uint64_t connection,const Frame& request) {
    const auto decoded=decode_richonline_room_kick27(request);
    auto& room=room_for_peer(connection);
    const auto actor=room.peers.at(connection).actor;
    if(room.owner!=actor) throw CodecError("richonline_room_kick_not_owner");
    if(decoded.room!=room.key) throw CodecError("richonline_room_kick_room_mismatch");
    if(decoded.target_actor==actor) throw CodecError("richonline_room_kick_self");
    if(room.game_pending) throw CodecError("richonline_room_kick_during_game");
    const auto target=std::find_if(room.peers.begin(),room.peers.end(),[&](const auto& item) {
        return item.second.actor==decoded.target_actor;
    });
    if(target==room.peers.end()) throw CodecError("richonline_room_kick_target_not_member");
    auto result=cancel_vote(room);
    append(result,broadcast(encode_richonline_room_kicked27(room.owner,actor,room.key,decoded.target_actor,decoded.reason())));
    profile_location(target->first,0xffffffffU,0xfffffffeU);
    room.peers.erase(target);
    log("room_peer_kicked key="+std::to_string(room.key));
    return result;
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::disconnect(std::uint64_t connection) {
    std::vector<RichonlineRoomDispatch> result;
    for (const auto& item : rooms_) if (item.second.peers.contains(connection)) { result = remove(connection); break; }
    const auto observer = observers_.find(connection);
    if (observer != observers_.end()) append(result, broadcast(scalars(55, {observer->second.actor})));
    observers_.erase(connection);
    std::erase_if(result, [connection](const auto& delivery) { return delivery.recipient == connection; });
    return result;
}

RichonlineVoteScope RichonlineRoomDirectory::vote_scope(const Room& room) const {
    RichonlineVoteScope scope{0,room.key,room.owner,{},room.game_pending};
    for(const auto& [connection,peer]:room.peers) scope.participants.push_back({connection,peer.actor});
    return scope;
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::cancel_vote(Room& room) {
    const auto resolution=room.vote.cancel();
    return resolution?resolve_vote(*resolution):std::vector<RichonlineRoomDispatch>{};
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::resolve_vote(const RichonlineVoteResolution& resolution) {
    const auto result_frame=encode_richonline_vote_result80(resolution.proposer,
        resolution.agree,resolution.oppose,resolution.abstain);
    std::vector<RichonlineRoomDispatch> result;
    for(const auto& member:resolution.scope.participants) {
        const auto observer=observers_.find(member.connection);
        if(observer!=observers_.end() && observer->second.actor==member.actor)
            result.push_back({member.connection,result_frame});
    }
    if(!resolution.approved()) return result;
    auto& room=rooms_.at(resolution.scope.room);
    // Poll/reply checked the electorate under the directory owner's lock. Map
    // metadata was validated at begin; any intervening edit cancels the vote.
    if(resolution.proposal.inner.wire_type==23) {
        const auto owner=std::find_if(room.peers.begin(),room.peers.end(),[&](const auto& item) {
            return item.second.actor==room.owner;
        });
        append(result,edit(owner->first,room.owner,resolution.proposal.inner.payload));
    } else {
        const auto target=*resolution.proposal.kick_target;
        const auto peer=std::find_if(room.peers.begin(),room.peers.end(),[target](const auto& item) {
            return item.second.actor==target;
        });
        auto remaining=room.peers;
        remaining.erase(peer->first);
        const auto owner=room.owner==target?remaining.begin()->second.actor:room.owner;
        const View reason=View(resolution.proposal.inner.payload).subspan(12,32);
        const auto end=std::find(reason.begin(),reason.end(),std::uint8_t{0});
        append(result,broadcast(encode_richonline_room_kicked27(owner,resolution.proposer,room.key,target,
            reason.first(static_cast<std::size_t>(end-reason.begin())))));
        profile_location(peer->first,0xffffffffU,0xfffffffeU);
        room.owner=owner;
        room.peers=std::move(remaining);
    }
    log("room_vote_applied key="+std::to_string(room.key)+" type="+std::to_string(resolution.proposal.inner.wire_type));
    return result;
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::vote_request(std::uint64_t connection,
    const Frame& request,RichonlineLobbyVote::Time now) {
    auto& room=room_for_peer(connection);
    if(request.wire_type==40) {
        const auto resolution=room.vote.reply(vote_scope(room),connection,decode_richonline_vote40(request),now);
        return resolution?resolve_vote(*resolution):std::vector<RichonlineRoomDispatch>{};
    }
    const auto proposal=decode_richonline_vote39(request);
    if(std::any_of(room.peers.begin(),room.peers.end(),[](const auto& item){return item.second.ready;}))
        throw CodecError("richonline_vote_while_ready");
    if(proposal.map_description) {
        const auto& description=*proposal.map_description;
        if(!same_client_metadata(room.description,description,room.owner,room.wire_slot))
            throw CodecError("richonline_room_metadata_update_unproven");
        // NEW6ADBB0 previews the map option byte at extension+84. Empty or
        // truncated map data would dereference outside the vote prompt.
        if(description.extension.size()!=88 || description.extension.front()==0 ||
            std::find(description.extension.begin(),description.extension.begin()+32,std::uint8_t{0})==description.extension.begin()+32)
            throw CodecError("richonline_vote_map_extension_invalid");
    }
    const auto prompt=encode_richonline_vote_prompt74(room.peers.at(connection).actor,proposal);
    std::vector<RichonlineRoomDispatch> result{{connection,encode_richonline_vote_started75(proposal.inner.wire_type)}};
    const auto resolution=room.vote.begin(vote_scope(room),connection,proposal,now);
    for(const auto& member:room.vote.electorate()) result.push_back({member.connection,prompt});
    if(resolution) append(result,resolve_vote(*resolution));
    return result;
}
std::vector<RichonlineRoomDispatch> RichonlineRoomDirectory::poll_votes(RichonlineLobbyVote::Time now) {
    std::vector<RichonlineRoomDispatch> result;
    for(auto& [key,room]:rooms_) {
        static_cast<void>(key);
        if(const auto resolution=room.vote.poll(vote_scope(room),now)) append(result,resolve_vote(*resolution));
    }
    return result;
}
}
