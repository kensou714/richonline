#pragma once
#include "richonline_inventory_date.hpp"
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace richnet {
enum class GameSettlementItemActivation { active, requires_activation };
struct GameSettlementItemInstance {
    std::uint32_t owned_key;
    // nullopt deliberately means an explicitly authorized permanent grant.
    // It must never be substituted for an unknown or unrepresentable expiry.
    std::optional<std::int64_t> expires_at;
    GameSettlementItemActivation activation;
};
struct GameSettlementItemSelection {
    std::uint32_t resource_index;
    std::uint32_t quantity;
    // Native inventory has count-one objects, keyed by full owned_key. Every
    // unit needs a distinct explicit key; identical keys are not merged.
    std::vector<GameSettlementItemInstance> instances;
};
struct GameSettlementItemResolution {
    std::string operation_id;
    std::string settlement_operation;
    std::string policy_identifier;
    std::string evidence;
    RichonlineInventoryDateVersion key_date_version;
    std::vector<GameSettlementItemSelection> selections;
};
struct GameSettlementItemClientGuard {
    RichonlineInventoryDateVersion date_version;
    std::string verified_client_compatibility_id;
};
enum class GameSettlementItemResolutionStatus { resolved, replayed, inventory_conflict, inventory_full };
struct GameSettlementResolvedItem {
    std::uint32_t resource_index;
    std::uint32_t original_owned_key;
    // Missing after consumption/expiry. Replay never restores an item. A
    // migration alias may map the immutable original receipt to a current key.
    std::optional<std::uint32_t> current_owned_key;
    std::optional<std::int64_t> expires_at;
    GameSettlementItemActivation activation;
};
struct GameSettlementItemResolutionResult {
    GameSettlementItemResolutionStatus status;
    std::vector<GameSettlementResolvedItem> items;
};
// Trusted administrator configuration only. There is no implicit pool draw,
// quantity, term, activation state, epoch, or inventory notification default.
GameSettlementItemResolution decode_game_settlement_item_resolution(const nlohmann::json& value);
}
