#pragma once

#include "server_lobby_adapter.hpp"
#include "richonline_room_directory.hpp"
#include <chrono>
#include <map>

namespace richnet {
struct RichonlineSocialResult {
    std::vector<RichonlineRoomDispatch> deliveries;
    std::string rejection;
};

// Called under the adapter's connection mutex. Invitations belong to live
// connection pairs; only accepted mutual friendships survive a restart.
class RichonlineSocial final {
public:
    RichonlineSocial(Storage& storage,const BootstrapBlobs& blobs,std::uint32_t server_id);
    ~RichonlineSocial();
    RichonlineSocial(const RichonlineSocial&)=delete;
    RichonlineSocial& operator=(const RichonlineSocial&)=delete;
    std::vector<RichonlineRoomDispatch> enter(std::uint64_t connection,const std::string& username,
        std::uint32_t role_id,std::uint32_t channel);
    std::vector<RichonlineRoomDispatch> leave(std::uint64_t connection);
    RichonlineSocialResult receive(std::uint64_t connection,const Frame& request);
private:
    struct Peer {std::string username;std::uint32_t role_id,channel;Bytes name;};
    using Pair=std::pair<std::uint64_t,std::uint64_t>;
    Storage& storage_;
    BootstrapBlobs blobs_;
    std::uint32_t server_id_;
    sqlite3* db_{};
    std::map<std::uint64_t,Peer> peers_;
    std::map<Pair,std::chrono::steady_clock::time_point> invitations_;
    std::vector<std::uint32_t> friends(std::uint32_t actor);
    LobbyRole role(std::uint32_t actor,const std::optional<std::string>& username=std::nullopt);
    Frame presence(const Peer& peer,bool online) const;
};
}
