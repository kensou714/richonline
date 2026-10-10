#pragma once

// 账号与角色持久层：管理 SQLite 连接、客户端版本隔离及大厅业务数据。

#include "credentials.hpp"
#include "bank.hpp"
#include "exchange.hpp"
#include "game_charge.hpp"
#include "game_settlement.hpp"
#include "game_settlement_items.hpp"
#include "lobby_inventory.hpp"
#include "richonline_mail.hpp"
#include "richonline_mall.hpp"
#include <filesystem>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <nlohmann/json.hpp>

struct sqlite3;

namespace richnet {
class StorageError : public std::runtime_error {
public:
    explicit StorageError(const std::string& code) : std::runtime_error(code) {}
};
enum class LoginOutcome { authenticated, registered, registration_disabled, invalid_credentials, password_mismatch };

class Storage {
public:
    explicit Storage(std::filesystem::path database_path,
                     ClientProfile profile = ClientProfile::richonline,
                     bool adopt_untagged_profile = false);
    ~Storage();
    Storage(const Storage&) = delete;
    Storage& operator=(const Storage&) = delete;
    nlohmann::json dispatch(std::string command, const nlohmann::json& payload);
    // 受信任的服务器脚本使用参数化批次；同一锁内提交，失败整体回滚。
    nlohmann::json script_batch(const nlohmann::json& request);
    bool verify_credentials(const std::string& username, std::span<const std::uint8_t> password);
    LoginOutcome login(const std::string& username, std::span<const std::uint8_t> password);
    nlohmann::json roles_for_username(const std::string& username);
    std::optional<std::string> preferences_for_username(const std::string& username);
    void save_preferences(const std::string& username, std::span<const std::uint8_t> payload);
    BankStatus transfer_bank(const std::string& username, std::int64_t role_id, const BankTransfer& transfer);
    ExchangeResult exchange_gold(const std::string& username, std::int64_t role_id, const GoldExchange& exchange);
    // Only trusted room admission may supply role_id; not a client lookup endpoint.
    GameAccount game_account_for_role(std::int64_t role_id);
    RichonlineMailMutation deliver_mail(const std::string& username,std::int64_t role_id,const RichonlineMailDelivery& delivery);
    RichonlineMailSendResult send_mail(const std::string& username,std::int64_t role_id,const RichonlineMailSend46& request,
        std::int64_t unix_now,const std::string& operation_id,RichonlineMailMetadataPolicy metadata);
    std::vector<RichonlineMailRecord88> mailbox(const std::string& username,std::int64_t role_id);
    RichonlineMailMutation read_mail(const std::string& username,std::int64_t role_id,RichonlineMailKey key);
    RichonlineMailMutation delete_mail(const std::string& username,std::int64_t role_id,RichonlineMailKey key);
    RichonlineMailClaimResult claim_mail(const std::string& username,std::int64_t role_id,const RichonlineMailClaim48& claim,std::int64_t unix_now);
    RichonlineMallPurchaseResult purchase_mall_item(const std::string& username,std::int64_t role_id,
        const RichonlineMallCatalog& catalog,const RichonlineMallPurchase& purchase,std::int64_t unix_now);
    void require_inventory_date_version(RichonlineInventoryDateVersion version);
    RichonlineMallActivationResult activate_mall_item(const std::string& username,std::int64_t role_id,
        const RichonlineMallCatalog& catalog,const RichonlineMallActivate63& request,std::int64_t unix_now,
        RichonlineInventoryDateVersion version,const std::string& operation_id,const std::string& evidence);
    GameGoldChargeResult consume_game_gold(const std::string& username, std::int64_t role_id,
                                          const GameGoldCharge& charge);
    GameEntryPledgeResult reserve_game_pledge(const std::string& username, std::int64_t role_id,
                                            const GameEntryPledgeRequest& request);
    GameEntryPledgeResult refund_game_pledge(const std::string& username, std::int64_t role_id,
                                           const GameEntryPledgeRefund& request);
    std::vector<GameSettlementOutbox> pending_game_settlements(const std::string& username, std::int64_t role_id);
    std::vector<GameSettlementProfileRefresh> pending_game_settlement_profile_refreshes(
        const std::string& username, std::int64_t role_id);
    // Stage the caller's current exact mode-0 profile; requires durable lobby
    // 58 delivery. Every retry invalidates the previous transport callback.
    GameSettlementProfileRefreshAttempt stage_game_settlement_profile_refresh(
        const std::string& username, std::int64_t role_id, const std::string& operation_id,
        std::uint32_t expected_wire_actor, const std::string& connection_generation,
        std::span<const std::uint8_t> profile);
    // Confirm only the current attempt's exact S2C19 whole-send callback.
    bool confirm_game_settlement_profile_refresh(const std::string& username, std::int64_t role_id,
        const GameSettlementProfileRefreshAttempt& attempt, std::uint16_t wire_type,
        std::span<const std::uint8_t> sent_profile);
    // Unresolved resource specifications, never a claim of inventory ownership.
    std::vector<GameSettlementPendingItemReward> pending_game_settlement_item_rewards(
        const std::string& username,std::int64_t role_id);
    GameSettlementItemResolutionResult resolve_game_settlement_items(const std::string& username,std::int64_t role_id,
        const RichonlineMallCatalog& catalog,const GameSettlementItemResolution& request,
        const GameSettlementItemClientGuard& client,std::int64_t unix_now);
    void advance_game_settlement_outbox(const std::string& username, std::int64_t role_id,
                                       const std::string& operation_id, std::uint32_t sent_message);
    GameSettlementResult settle_game(const std::string& username, std::int64_t role_id,
                                     const GameSettlementRequest& request);
    nlohmann::json select_model(const std::string& username, std::int64_t role_id, std::uint32_t model);
    // unix_now 使用 Unix 时间戳（秒），用于判断库存有效期；不是单调时钟计数。
    LobbyInventory lobby_inventory(const std::string& username, std::int64_t role_id, std::int64_t unix_now);
    LobbyInventory lobby_inventory_for_role(std::int64_t role_id, std::int64_t unix_now);
    RpCertificateGrant ensure_test_rp_certificate(const std::string& username, std::int64_t unix_now);
    void update_lobby_equipment(const std::string& username, const LobbyEquipmentChange& change, std::int64_t unix_now);
    ClientProfile client_profile() const noexcept { return profile_; }
    const std::filesystem::path& database_path() const noexcept { return path_; }
    static std::filesystem::path import_database(const std::filesystem::path& source,
                                                 const std::filesystem::path& destination);
private:
    sqlite3* db_{};
    std::filesystem::path path_;
    ClientProfile profile_;
    std::mutex mutex_;
    nlohmann::json list_accounts(const nlohmann::json& payload);
    nlohmann::json create_account(const nlohmann::json& payload);
    nlohmann::json create_account_with_verifier(const std::string& username,
        const CredentialVerifier& verifier, const std::string& source);
    nlohmann::json update_account(const nlohmann::json& payload);
    nlohmann::json get_config();
    nlohmann::json update_config(const nlohmann::json& payload);
    nlohmann::json backup();
};
}
