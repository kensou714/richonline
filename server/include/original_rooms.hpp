#pragma once

#include "lobby.hpp"
#include "original_room_description.hpp"

#include <functional>
#include <map>
#include <memory>
#include <set>

namespace richnet {
class OriginalGameHost;

// Owned by one lobby select loop; database profile readers may also serve the manager.
class OriginalRoomDirectory final {
public:
    using ProfileSource = std::function<Bytes()>;
    OriginalRoomDirectory(std::shared_ptr<const OriginalMapCatalog> maps, std::uint32_t capacity, LobbyLogSink log = {},
                          std::shared_ptr<OriginalGameHost> host = {}, std::uint32_t channel = 0);
    void enter(std::uint32_t user, ProfileSource profile);
    void disconnect(std::uint32_t user);
    std::vector<Frame> drain(std::uint32_t user);
    void request(std::uint32_t user, const Frame& frame);
    void model_changed(std::uint32_t user, std::uint32_t model);
    Bytes profile(std::uint32_t user) const;
    Bytes apply_membership(std::uint32_t user, Bytes profile) const;
    bool ready(std::uint32_t user) const;
private:
    struct Participant {
        ProfileSource source;
        std::vector<Frame> pending;
        std::size_t pending_bytes = 0;
        bool overflow = false;
        std::set<std::uint32_t> known_users;
    };
    struct Game {
        struct Member { std::uint32_t slot; std::uint32_t team; };
        std::uint32_t owner;
        OriginalGameDescription description;
        std::map<std::uint32_t, Member> slots;
        std::set<std::uint32_t> ready_users;
        std::optional<std::uint64_t> launch;
    };
    std::shared_ptr<const OriginalMapCatalog> maps_;
    std::uint32_t capacity_;
    LobbyLogSink log_;
    std::map<std::uint32_t, Participant> participants_;
    std::map<std::uint32_t, Game> games_;
    std::shared_ptr<OriginalGameHost> host_;
    std::uint32_t channel_;
    std::uint64_t next_launch_ = 1;
    std::optional<std::uint32_t> game_for(std::uint32_t user) const;
    void enqueue(std::uint32_t user, const Frame& frame);
    void broadcast(const Frame& frame);
    void send_profile(std::uint32_t recipient, std::uint32_t user);
    void snapshot(std::uint32_t user, std::uint32_t id, const Game& game);
    void leave(std::uint32_t user);
    Bytes configuration(const Game& game) const;
    void start_game(std::uint32_t id, std::uint32_t last_ready_user);
    void refresh_games();
    bool finish_game(std::uint32_t id);
    void publish_configuration(std::uint32_t id, const Game& game);
};
}
