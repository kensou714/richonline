#pragma once

// 新版大厅业务适配：把协议模板、持久层、频道目录及游戏登记接入大厅回调。

#include "control.hpp"
#include "lobby.hpp"
#include "storage.hpp"
#include "richonline_game_registry.hpp"
#include "richonline_mall_service.hpp"
#include "channel_catalog.hpp"

#include <array>
#include <filesystem>
#include <memory>
#include <optional>

namespace richnet {

struct RichonlineMailBootstrapPolicy {
    std::string provenance;
    RichonlineMailMetadataPolicy metadata;
};
struct BootstrapBlobs {
    std::string provenance;
    std::array<std::uint8_t, 80> unknown_channel_record;
    std::array<std::uint8_t, 208> unknown_role_record;
    std::array<std::uint8_t, 272> unknown_profile_record;
    std::array<std::uint8_t, 16> unknown_login_result;
    std::array<std::uint8_t, 16> unknown_identity_record;
    std::array<std::uint8_t, 4> unknown_empty_list;
    std::array<std::uint8_t, 32> unknown_bank_config;
    std::array<std::uint8_t, 28> unknown_completion;
    std::uint32_t game_capacity;
    std::uint32_t player_capacity;
    Bytes stage_progress;
    std::string setting_text;
    std::optional<std::uint32_t> room_unknown_prefix;
    ChannelCatalog channels{};
    bool grant_test_rp_certificate = false;
    // Native friend presence resolves this ID with Config/Serverlist.kpd.
    std::optional<std::uint32_t> social_server_id{};
    std::optional<RichonlineMailBootstrapPolicy> richonline_mail_policy{};
    std::optional<RichonlineMallCompatibilityPolicy> richonline_mall_policy{};
};

struct LobbyRole {
    std::uint32_t id, model, purchase_score, level, wins, losses, draws, experience, vip_level, escapes;
    double coins, gold, bank;
    Bytes name;
};
LobbyRole parse_lobby_role(const nlohmann::json& record);
Bytes encode_lobby_role_record(const LobbyRole& role,const BootstrapBlobs& blobs,const LobbyInventory& inventory);

BootstrapBlobs load_bootstrap_blobs(const std::filesystem::path& path);
void validate_bootstrap_blobs(const BootstrapBlobs& blobs);

struct ServerLobbyOptions {
    std::string host = "127.0.0.1";
    std::uint16_t port = 18600;
    LobbyHandshake handshake = local_lobby_handshake();
    LobbyOptions transport() const;
};

class ServerLobbyAdapter final {
public:
    ServerLobbyAdapter(Storage& storage, BootstrapBlobs blobs, ControlLog log = {});
    LobbyCallbacks callbacks();
    void set_game_registry(std::shared_ptr<RichonlineGameRegistry> registry);
    void set_mall_catalog(std::shared_ptr<const RichonlineMallCatalog> catalog);
    std::uint32_t channel_player_count(std::uint32_t channel) const;
private:
    struct Connections;
    std::vector<Frame> login_responses(const LobbyLogin& login);
    std::vector<Frame> authenticated_request(const LobbyLogin& login, const Frame& frame);
    std::vector<Frame> account_request(const LobbyLogin& login,std::uint32_t role_id,const Frame& frame);
    std::vector<Frame> channel_responses(const LobbyLogin& login, std::uint32_t selected, std::uint32_t channel);
    Frame profile_refresh(const std::string& username,std::uint32_t selected,const nlohmann::json& current_role);
    void queue_pending_profile_refreshes(std::uint64_t connection);
    Storage& storage_;
    BootstrapBlobs blobs_;
    ControlLog log_;
    std::shared_ptr<Connections> connections_;
    std::shared_ptr<RichonlineGameRegistry> game_registry_;
    std::shared_ptr<const RichonlineMallCatalog> mall_catalog_;
};

}
