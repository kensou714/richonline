#pragma once

#include "richonline_auxiliary.hpp"
#include "richonline_achievement.hpp"
#include <filesystem>
#include <mutex>

struct sqlite3;
namespace richnet {
// NEW category-table IDs are independent of the five achievement rank IDs.
enum class RichonlineAccountRanking : std::int32_t { wins = 1, level = 2, gold = 3 };
// Legacy/import writer for an owned match whose settlement is already committed.
// Production sessions supply GameSettlementRequest::achievement atomically.
// Each observation is
// immutable and bound to an owned role and match; retrying cannot add it twice.
class RichonlineAchievementStore final {
public:
    explicit RichonlineAchievementStore(const std::filesystem::path& database);
    ~RichonlineAchievementStore();
    RichonlineAchievementStore(const RichonlineAchievementStore&) = delete;
    RichonlineAchievementStore& operator=(const RichonlineAchievementStore&) = delete;
    bool record_match(const std::string& username, std::int64_t role_id,
        const std::string& match_id, RichonlineAchievement category,
        std::uint64_t score, const std::string& policy);
private:
    sqlite3* db_{};
    std::mutex mutex_;
};

class RichonlineRankingStore final {
public:
    explicit RichonlineRankingStore(const std::filesystem::path& database);
    ~RichonlineRankingStore();
    RichonlineRankingStore(const RichonlineRankingStore&) = delete;
    RichonlineRankingStore& operator=(const RichonlineRankingStore&) = delete;
    std::optional<Bytes> response(View request);
private:
    sqlite3* db_{};
    std::mutex mutex_;
};
}
