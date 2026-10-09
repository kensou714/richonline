#pragma once

#include "richonline_achievement.hpp"

struct sqlite3;
namespace richnet::storage_detail {
void validate_richonline_achievement(const GameSettlementAchievement& achievement);
void richonline_achievement_schema(sqlite3* db);
// The caller owns the transaction and has inserted the matching settlement.
bool insert_richonline_achievement(sqlite3* db,std::int64_t role_id,const std::string& match_id,
    const std::string& operation,const GameSettlementAchievement& achievement);
// A settled operation replay must already have its atomically committed metric.
void verify_richonline_achievement(sqlite3* db,std::int64_t role_id,const std::string& match_id,
    const std::string& operation,const GameSettlementAchievement& achievement);
}
