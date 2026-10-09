#pragma once
#include "richonline_boss_turns.hpp"
#include "richonline_game_ledger.hpp"

namespace richnet {
enum class RichonlineSpecialContinuation { property_phase2, awaiting_server_event };
enum class RichonlineSpecialOutcome { controlled_skip, scripted_skip, insufficient_tickets, merchant_exchange, server_event_required };
struct RichonlineSpecialLandingContext {
    RichonlineLandingContext landing;
    // NEW game+83830 != -1 bypasses the static dispatcher. The session owner
    // supplies its actual scripted-event state; this is not a packet byte.
    bool scripted_event_active;
};
class RichonlinePreparedSpecialLanding {
public:
    std::uint8_t actor() const noexcept {return actor_;}
    RichonlineSpecialContinuation continuation() const noexcept {return continuation_;}
    RichonlineSpecialOutcome outcome() const noexcept {return outcome_;}
    const std::vector<Bytes>& messages() const noexcept {return messages_;}
    const RichonlineGameFundsSnapshot& before() const noexcept {return before_;}
    const RichonlineGameFunds& after() const noexcept {return after_;}
    bool expects_client_request() const noexcept {return false;}
private:
    RichonlinePreparedSpecialLanding()=default;
    std::uint8_t actor_=0;
    RichonlineActorStatus status_{};
    RichonlineGameFundsSnapshot before_{};
    RichonlineGameFunds after_{};
    RichonlineSpecialContinuation continuation_=RichonlineSpecialContinuation::property_phase2;
    RichonlineSpecialOutcome outcome_=RichonlineSpecialOutcome::controlled_skip;
    std::vector<Bytes> messages_;
    bool committed_=false;
    friend std::optional<RichonlinePreparedSpecialLanding> prepare_richonline_special_landing(
        std::uint16_t,const RichonlineSpecialLandingContext&,const RichonlineGameFundsSnapshot&);
    friend bool commit_richonline_special_landing(RichonlineGameLedger&,RichonlinePreparedSpecialLanding&,
        const RichonlineActorStatus&,const std::function<bool()>&);
};
// Mode3 static57 and58 only. Preparation never mutates funds/status. A57
// response contains only4013: NEW locally exchanges25 tickets for2000 cash;
// sending an additional monetary delta would apply the exchange twice.
std::optional<RichonlinePreparedSpecialLanding> prepare_richonline_special_landing(
    std::uint16_t game,const RichonlineSpecialLandingContext&,const RichonlineGameFundsSnapshot&);
// Commit only closed phase2 plans. A58 event requirement cannot be committed as
// a successful landing: its event owner must prepare a proven effect/response.
// authorize must not reenter the ledger and runs after every balance check.
bool commit_richonline_special_landing(RichonlineGameLedger&,RichonlinePreparedSpecialLanding&,
    const RichonlineActorStatus&,const std::function<bool()>& authorize);
}
