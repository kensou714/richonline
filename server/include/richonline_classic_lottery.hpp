#pragma once

#include "richonline_game_ledger.hpp"
#include "richonline_boss_turns.hpp"

namespace richnet {
struct RichonlineLotteryRequest {
    std::uint16_t calendar;
    std::int8_t number;
    std::uint8_t opaque_tail;
};
RichonlineLotteryRequest decode_richonline_lottery_request(View request);
struct RichonlineLotteryEntry {
    std::uint16_t game_id,calendar;
    std::uint64_t sequence;
    std::uint8_t actor;
    std::int16_t position;
    bool operator==(const RichonlineLotteryEntry&) const = default;
};
struct RichonlineLotteryPurchase {
    Bytes message;
    RichonlineLotteryEntry entry;
    std::int8_t number;
    bool timed_out;
};
struct RichonlineLotteryDraw {
    Bytes message;
    std::uint8_t number;
    std::int8_t winner;
    std::uint32_t prize;
};
// 号码与待决购买独占一局；奖池沿用会话的G+C80新闻累计项，不创建第二份余额。
class RichonlineClassicLottery final {
public:
    using Now=std::function<std::chrono::steady_clock::time_point()>;
    RichonlineClassicLottery(std::uint16_t game,std::shared_ptr<RichonlineGameLedger> ledger,
        Now now,std::chrono::milliseconds timeout,RichonlineRouteChooser random,
        std::array<std::uint8_t,2> draw_opaque,std::shared_ptr<LuaServer> script);
    bool has_numbers() const noexcept;
    bool can_buy(std::uint8_t actor) const;
    void begin(const RichonlineLotteryEntry& entry);
    RichonlineLotteryPurchase handle(std::uint8_t sender,View request,
        const RichonlineLotteryEntry& current,std::uint32_t& jackpot);
    std::optional<RichonlineLotteryPurchase> poll(const RichonlineLotteryEntry& current,std::uint32_t& jackpot);
    // 调度层已确认当月15日轮首；相同scan_id不重复抽取或派奖。
    std::optional<RichonlineLotteryDraw> draw(std::uint64_t scan_id,std::span<const std::uint8_t> active,
        std::uint32_t& jackpot);
    // 7BE160 -> 7D9CC0只释放该角色号码，不退购票款、不重置奖池。
    void retire(std::uint8_t actor) noexcept;
private:
    struct Pending { RichonlineLotteryEntry entry;std::chrono::steady_clock::time_point deadline; };
    void validate_pending(const RichonlineLotteryEntry& current) const;
    RichonlineLotteryPurchase finish(std::int8_t number,bool timed_out,std::uint32_t& jackpot);
    std::uint16_t game_;
    std::shared_ptr<RichonlineGameLedger> ledger_;
    Now now_;
    std::chrono::milliseconds timeout_;
    RichonlineRouteChooser random_;
    std::array<std::uint8_t,2> draw_opaque_;
    std::shared_ptr<LuaServer> script_;
    std::array<std::int8_t,32> owners_{};
    std::optional<Pending> pending_;
    std::uint64_t last_draw_=0;
};
}
