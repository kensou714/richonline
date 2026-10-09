#pragma once

#include "lobby.hpp"
#include "storage.hpp"

#include <filesystem>
#include <memory>

namespace richnet {
class OriginalMapCatalog;
class OriginalGameHost;
struct OriginalLobbyPolicy {
    std::string provenance;
    Bytes room_template;
    Bytes role_template;
    Bytes profile_template;
    Bytes login_template;
    Bytes identity_template;
    Bytes bank_template;
    Bytes completion_template;
    std::uint32_t room_id;
    std::uint32_t game_capacity;
    std::uint32_t player_capacity;
    std::uint32_t item_grid_count;
    std::uint32_t item_per_space;
    Bytes stage_progress;
    std::string setting_text;
    std::uint32_t tutorial_dismissal_mask;
    std::optional<std::int32_t> exchange_ratio = std::nullopt;
    std::shared_ptr<const OriginalMapCatalog> maps = {};
};

void validate_original_lobby_policy(const OriginalLobbyPolicy& policy);
OriginalLobbyPolicy load_original_lobby_policy(const std::filesystem::path& path);
LobbyCallbacks make_original_lobby_callbacks(Storage& original_storage, OriginalLobbyPolicy policy);
LobbyCallbackFactory make_original_lobby_factory(Storage& original_storage, OriginalLobbyPolicy policy, LobbyLogSink log = {},
                                                 std::shared_ptr<OriginalGameHost> host = {});
}
