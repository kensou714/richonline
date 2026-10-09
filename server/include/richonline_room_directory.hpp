#pragma once

// 新版房间目录：以连接和角色身份管理成员、准备状态、角色切换与开局快照。

#include "richonline_room_protocol.hpp"
#include "richonline_lobby_vote.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace richnet {

struct RichonlineRoomPeer {
    std::uint64_t connection;
    std::uint32_t actor;
    std::uint32_t slot;
    bool ready;
    std::uint32_t team = 0;
};

struct RichonlineRoomDispatch {
    std::uint64_t recipient;
    Frame frame;
};
struct RichonlineRoomPolicy {
    std::uint32_t unknown_prefix;
    std::uint32_t room_capacity;
};
struct RichonlineRoomSnapshot {
    std::uint32_t key;
    std::uint32_t owner;
    RichonlineRoomDescription description;
    std::vector<RichonlineRoomPeer> participants;
    std::uint32_t channel = 0;
};

using RichonlineRoomLog = std::function<void(const std::string&)>;

class RichonlineRoomDirectory final {
public:
    explicit RichonlineRoomDirectory(RichonlineRoomPolicy policy, RichonlineRoomLog log = {});
    std::vector<RichonlineRoomDispatch> enter(std::uint64_t connection, std::uint32_t actor, Frame profile);
    std::vector<RichonlineRoomDispatch> receive(std::uint64_t connection, std::uint32_t actor, const Frame& request,
        RichonlineLobbyVote::Time now = RichonlineLobbyVote::Clock::now());
    std::vector<RichonlineRoomDispatch> poll_votes(RichonlineLobbyVote::Time now = RichonlineLobbyVote::Clock::now());
    std::vector<RichonlineRoomDispatch> disconnect(std::uint64_t connection);
    std::vector<RichonlineRoomDispatch> select_character(std::uint64_t connection, std::uint32_t character,
                                                        const std::function<void()>& persist);
    std::optional<RichonlineRoomSnapshot> ready_game(std::uint64_t connection);
    std::optional<std::uint32_t> room_key(std::uint64_t connection) const;
    Frame current_profile(std::uint64_t connection, std::uint32_t actor) const;
    void refresh_profile(std::uint64_t connection, std::uint32_t actor,
                         const Frame& expected_current, const Frame& update);
    void set_game_pending(std::uint64_t connection, bool pending);
    bool game_pending(std::uint64_t connection) const;
    std::vector<RichonlineRoomDispatch> game_finished(std::uint32_t room_key);
    std::size_t room_count() const noexcept { return rooms_.size(); }
    std::size_t peer_count(std::uint32_t room_key) const;
private:
    struct Room {
        std::uint32_t key;
        RichonlineRoomDescription description;
        std::uint32_t owner;
        std::map<std::uint64_t, RichonlineRoomPeer> peers;
        std::uint32_t wire_slot = 0;
        bool game_pending = false;
        RichonlineLobbyVote vote;
    };
    struct Observer { std::uint32_t actor; Frame profile; };
    std::vector<RichonlineRoomDispatch> create(std::uint64_t connection, std::uint32_t actor, View payload);
    std::vector<RichonlineRoomDispatch> join(std::uint64_t connection, std::uint32_t actor, View payload);
    std::vector<RichonlineRoomDispatch> prepare(std::uint64_t connection, View payload, bool ready);
    std::vector<RichonlineRoomDispatch> leave(std::uint64_t connection, View payload);
    std::vector<RichonlineRoomDispatch> edit(std::uint64_t connection, std::uint32_t actor, View payload);
    std::vector<RichonlineRoomDispatch> select_team(std::uint64_t connection, const Frame& request);
    std::vector<RichonlineRoomDispatch> kick(std::uint64_t connection, const Frame& request);
    RichonlineVoteScope vote_scope(const Room& room) const;
    std::vector<RichonlineRoomDispatch> vote_request(std::uint64_t connection, const Frame& request,
        RichonlineLobbyVote::Time now);
    std::vector<RichonlineRoomDispatch> resolve_vote(const RichonlineVoteResolution& resolution);
    std::vector<RichonlineRoomDispatch> cancel_vote(Room& room);
    Room& room_for_peer(std::uint64_t connection);
    std::vector<RichonlineRoomDispatch> broadcast(const Frame& frame) const;
    std::vector<RichonlineRoomDispatch> remove(std::uint64_t connection);
    void log(const std::string& message) const;
    void profile_location(std::uint64_t connection, std::uint32_t key, std::uint32_t team);
    RichonlineRoomLog log_;
    RichonlineRoomPolicy policy_;
    std::map<std::uint32_t, Room> rooms_;
    std::map<std::uint64_t, Observer> observers_;
    std::uint32_t next_key_ = 1;
};

}
