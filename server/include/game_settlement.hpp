#pragma once

#include "richonline_achievement.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace richnet {
struct GameEntryPledgeRequest {
    std::string operation_id;
    std::string match_id;
    std::string stage_key;
    std::uint32_t amount;
};
struct GameEntryPledgeResult {
    bool replayed;
    double gold_after;
};
struct GameEntryPledgeRefund {
    std::string operation_id;
    std::string pledge_operation;
    std::string reason;
};
enum class GameOutcome { win, loss, draw };
struct GameSettlementDelivery {
    std::uint16_t game_id;
    std::uint32_t room_id;
    std::int8_t human_slot;
    std::int8_t rank_image_index;
    std::uint8_t opaque_18;
    bool show_text_270;
    std::vector<std::int8_t> bankrupt_slots;
    // 版本1误把400D发给败者；版本2为每个败者发400E，仅向胜者发400D。
    std::uint8_t message_version=2;
};
struct GameSettlementItemReward {
    // Raw stage resource specification. These are not an inventory grant count
    // or selected owned keys; original selection/expiry policy remains unresolved.
    std::uint32_t resource_count;
    std::vector<std::int32_t> resource_ids;
    bool operator==(const GameSettlementItemReward&) const = default;
};
struct GameSettlementReward {
    std::uint32_t experience;
    // Actual amount credited, including any returned entry pledge. The result
    // UI subtracts the pledge; this is not the account's ending gold balance.
    std::uint32_t gold_return;
    std::uint32_t bonus_gold;
    std::optional<GameSettlementItemReward> items{};
};
struct GameSettlementPolicy {
    std::string provenance;
    GameSettlementReward first_win;
    GameSettlementReward repeat_win;
    GameSettlementReward loss;
    GameSettlementReward draw;
    std::array<std::uint32_t,21> cumulative_level_experience;
    // Principal included in both win gold_return amounts by a resource policy.
    // Storage verifies it never exceeds this match's genuinely held pledge.
    std::uint32_t winning_pledge_return;
};
struct GameSettlementRequest {
    std::string operation_id;
    std::string match_id;
    std::string stage_key;
    GameOutcome outcome;
    std::uint32_t pawn_gold;
    // Nonzero entry stakes require a held entry pledge bound to this match.
    std::optional<std::string> pledge_charge_operation;
    GameSettlementPolicy policy;
    std::optional<GameSettlementDelivery> delivery{};
    std::optional<GameSettlementAchievement> achievement{};
};
struct GameSettlementResult {
    bool replayed;
    bool first_clear;
    GameSettlementReward reward;
    std::uint32_t level_before;
    std::uint32_t level_after;
    std::uint32_t experience_after;
    double gold_after;
    std::uint32_t wins_after;
    std::uint32_t losses_after;
    std::uint32_t draws_after;
};
struct GameSettlementOutbox {
    std::string operation_id;
    std::string match_id;
    GameOutcome outcome;
    GameSettlementDelivery delivery;
    GameSettlementResult result;
    std::uint32_t next_message;
};
// Durable notification intent created atomically with settlement. It carries
// no cached account values: the sender must materialize the latest profile
// after the participant's exact lobby 58 whole-send confirmation.
struct GameSettlementProfileRefresh {
    std::string operation_id;
    std::string match_id;
    std::int64_t role_id;
};
struct GameSettlementProfileRefreshAttempt {
    GameSettlementProfileRefresh intent;
    std::string connection_generation;
    std::int64_t attempt;
    std::array<std::uint8_t,144> profile;
};
struct GameSettlementPendingItemReward {
    std::string operation_id;
    std::string match_id;
    std::string stage_key;
    std::string provenance;
    GameSettlementItemReward specification;
};
}
