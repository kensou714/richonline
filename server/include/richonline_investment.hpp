#pragma once

#include "richonline_game_ledger.hpp"
#include "richonline_route.hpp"
#include "richonline_boss_stage.hpp"
#include <chrono>
#include <memory>

namespace richnet {
// NEW static67 is an investment collection point. BossWar's investBase and
// investReturn are resource fields, not an inferred fee or reward constant.
struct RichonlineInvestmentRules {
    std::uint32_t invest_base,invest_return;
    std::vector<std::int16_t> positions;
};
RichonlineInvestmentRules make_richonline_investment_rules(const RichonlineRoadTopology&,
    std::uint32_t invest_base,std::uint32_t invest_return);
// Selected map's actual resource values are mandatory when it contains67.
// A map without67 is dormant; its absent fields need no gameplay substitute.
RichonlineInvestmentRules make_richonline_investment_rules(const RichonlineRoadTopology&,
    const RichonlineBossStage&);

struct RichonlineInvestmentPassRequest { std::uint16_t calendar_counter; std::int16_t position; };
struct RichonlineInvestmentRequest {
    std::uint16_t calendar_counter;
    bool accept;
    std::uint8_t unassigned5;
};
RichonlineInvestmentPassRequest decode_richonline_investment_pass(View);
RichonlineInvestmentRequest decode_richonline_investment_request(View);

enum class RichonlineInvestmentVisit { passing,landing };
enum class RichonlineInvestmentContinuation { await_choice,continue_movement,resume_movement,continue_landing };
enum class RichonlineInvestmentOutcome { opened,purchased,declined,timed_out,synthetic_decline,
    already_collected,insufficient_cash,static_effect_skipped,collection_reward };
struct RichonlineInvestmentEntry {
    std::uint8_t actor_slot;
    std::int16_t position;
    std::uint16_t calendar_counter;
    RichonlineInvestmentVisit visit;
    bool synthetic_actor;
    // Caller derives this from the NEW movement/landing guards, including
    // actor1488==7, actor1499 and game83830. Never infer it from synthetic alone.
    bool client_static_effect_allowed;
};
struct RichonlineInvestmentState {
    std::array<bool,9> collected{};
    std::uint64_t revision=0;
    bool operator==(const RichonlineInvestmentState&) const = default;
};
struct RichonlineInvestmentResult {
    std::vector<Bytes> messages;
    RichonlineInvestmentEntry entry;
    RichonlineInvestmentState before,after;
    RichonlineGameFundsSnapshot funds_before,funds_after;
    RichonlineInvestmentContinuation continuation;
    RichonlineInvestmentOutcome outcome;
};
class RichonlineInvestment final {
public:
    using Clock=std::chrono::steady_clock;
    using Now=std::function<Clock::time_point()>;
    RichonlineInvestment(std::uint16_t game_id,RichonlineInvestmentRules,
        std::shared_ptr<RichonlineGameLedger>,std::uint8_t admission_opaque7,Now);
    // Called exactly once at an actual visited static67, in route order. A
    // complete collection is rewarded on the NEXT visit, before checking this
    // point's flag, and sends no funds packet: NEW already applies it locally.
    RichonlineInvestmentResult begin(const RichonlineInvestmentEntry&);
    RichonlineInvestmentResult handle(View);
    std::optional<RichonlineInvestmentResult> poll();
    bool active() const noexcept { return pending_.has_value(); }
    RichonlineInvestmentState state(std::uint8_t actor) const;
    const RichonlineInvestmentRules& rules() const noexcept { return rules_; }
private:
    struct Pending {
        RichonlineInvestmentEntry entry;
        RichonlineInvestmentState state;
        RichonlineGameFundsSnapshot funds;
        std::size_t position_index;
        Clock::time_point deadline;
    };
    std::uint16_t game_id_;
    RichonlineInvestmentRules rules_;
    std::shared_ptr<RichonlineGameLedger> ledger_;
    std::uint8_t admission_opaque7_;
    Now now_;
    std::array<RichonlineInvestmentState,8> states_{};
    std::optional<Pending> pending_;
    RichonlineInvestmentResult finish(bool accept,RichonlineInvestmentOutcome);
};
}
