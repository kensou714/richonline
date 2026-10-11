#pragma once

#include "richonline_player_cards.hpp"
#include "richonline_game_ledger.hpp"
#include "richonline_raw_authority.hpp"

#include <chrono>

namespace richnet {
// Feast.kpd的31年×13槽月日表；同日重合只取资源中最先出现的槽。
class RichonlineFeastResources final {
public:
    static RichonlineFeastResources parse(View decoded);
    static RichonlineFeastResources load(const std::filesystem::path& root);
    std::optional<std::uint8_t> find(std::chrono::year_month_day date) const;
private:
    RichonlineFeastResources()=default;
    std::array<std::array<std::array<std::uint8_t,2>,13>,31> dates_{};
};
enum class RichonlineFeastRelease { none,hospital,jail };
struct RichonlineClassicFeastChange {
    std::uint8_t actor;
    RichonlineGameFundsSnapshot before_funds;
    RichonlineGameFunds after_funds;
    RichonlineChanceInventory before_inventory,after_inventory;
    RichonlineActorStatus before_status,after_status;
    RichonlineRawActorState before_raw;
    RichonlineFeastRelease release=RichonlineFeastRelease::none;
};
struct RichonlineClassicFeastPlan {
    std::uint8_t slot;
    std::vector<RichonlineClassicFeastChange> changes;
    std::vector<Bytes> messages;
};
// 仅准备：资金、卡片、状态及网络消息全部成功后，会话再共同提交。
// 不在此推进日历、发4010、等待0015或扫描研究所，避免隐藏调度副作用。
RichonlineClassicFeastPlan prepare_richonline_classic_feast(std::uint8_t slot,std::uint16_t game_id,
    std::span<const std::uint8_t> active,std::span<const RichonlineActorStatus> statuses,
    const RichonlineRawAuthority& raw,const RichonlineGameLedger& ledger,
    std::span<const std::shared_ptr<RichonlinePlayerCards>> cards,
    const RichonlineRouteChooser& random,const std::shared_ptr<LuaServer>& script);
}
