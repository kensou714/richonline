#include "original_rooms.hpp"
#include "original_game_host.hpp"
#include <algorithm>

namespace richnet {
namespace {
Bytes words(std::initializer_list<std::uint32_t> values) {
    Bytes bytes;
    for (const auto value : values) append_le(bytes,value,4);
    return bytes;
}
}
void OriginalRoomDirectory::publish_configuration(std::uint32_t id, const Game& game) {
    auto bytes = words({id});
    const auto config = configuration(game);
    bytes.insert(bytes.end(),config.begin(),config.end());
    broadcast({26,std::move(bytes)});
}
void OriginalRoomDirectory::start_game(std::uint32_t id, std::uint32_t last_ready_user) {
    auto& game = games_.at(id);
    std::optional<std::uint64_t> generation;
    try {
        if (!host_) throw CodecError("game_runtime_not_configured");
        if (game.slots.size() < read_le(View(game.description.wire).subspan(40,4)))
            throw CodecError("original_room_minimum_players_required");
        if (next_launch_ == 0) throw CodecError("original_room_generation_exhausted");
        generation = next_launch_++;
        auto description = game.description;
        description.wire = configuration(game);
        OriginalRoomSnapshot snapshot{*generation,channel_,id,game.owner,std::move(description),{}};
        for (const auto& [user,member] : game.slots)
            snapshot.players.push_back({user,member.slot,member.team,profile(user)});
        std::sort(snapshot.players.begin(),snapshot.players.end(),[](const auto& left,const auto& right) {
            return left.slot < right.slot;
        });
        const auto redirects = host_->prepare(snapshot);
        game.launch = generation;
        publish_configuration(id,game);
        for (const auto& redirect : redirects) enqueue(redirect.user_id,redirect.message);
        if (log_) log_("original_room_game_prepared game_id="+std::to_string(id)+" generation="+std::to_string(*generation));
    } catch (const CodecError& error) {
        if (generation) host_->retire(*generation);
        if (game.launch) { game.launch.reset(); publish_configuration(id,game); }
        if (log_) log_("original_room_request_rejected request_type=5 reason="+std::string(error.what()));
        for (const auto user : game.ready_users)
            if (user != last_ready_user) broadcast({96,words({user,id})});
        broadcast({96,words({last_ready_user,id})});
        game.ready_users.clear();
    }
}
bool OriginalRoomDirectory::finish_game(std::uint32_t id) {
    auto& game = games_.at(id);
    const auto admitted = game.launch && host_->retire(*game.launch).admitted;
    game.launch.reset();
    if (admitted) {
        std::vector<std::uint32_t> users;
        for (const auto& [user,member] : game.slots) { static_cast<void>(member); users.push_back(user); }
        for (const auto user : users) leave(user);
    } else {
        publish_configuration(id,game);
        for (const auto user : game.ready_users) broadcast({96,words({user,id})});
        game.ready_users.clear();
    }
    return admitted;
}
void OriginalRoomDirectory::refresh_games() {
    if (!host_) return;
    std::vector<std::uint32_t> complete;
    for (const auto& [id,game] : games_) {
        if (!game.launch) continue;
        const auto status = host_->status(*game.launch);
        if (status.finished) {
            complete.push_back(id);
        }
    }
    for (const auto id : complete) finish_game(id);
}
}
