#pragma once

#include "richonline_terminal.hpp"
#include "richonline_game_ledger.hpp"
#include <memory>

namespace richnet {
enum class RichonlineTerminalPhase { prepared, playing, delivering, finished, aborted, recovery_required };
enum class RichonlineTerminalAction { continue_play, deliver, abort_live_game, finished };
struct RichonlineTerminalStep {
    RichonlineTerminalAction action;
    std::vector<Bytes> game_messages;
    std::string diagnostic;
};
enum class RichonlineTerminalAbandonAction { startup_refunded, loss_persisted, already_terminal, recovery_required };
struct RichonlineTerminalAbandonResult {
    RichonlineTerminalAbandonAction action;
    std::optional<GameEntryPledgeResult> startup_refund;
    std::optional<GameSettlementResult> settlement;
    std::string diagnostic;
};
struct RichonlineTerminalContext {
    std::string username;
    std::int64_t role_id;
    std::uint16_t game_id;
    std::uint32_t room_id;
    GameSettlementRequest settlement;
    RichonlineTerminalSnapshot roster;
    RichonlineTerminalRules rules;
    // An explicit evidence reference is required before writing 401B+18.
    // An empty reference is an unresolved contract, never an implicit zero.
    std::string result_byte18_evidence;
};

// One instance belongs to one live match. Storage outbox recovery after process
// loss remains explicit because the original client sends no settlement ACK.
class RichonlineTerminalCoordinator {
public:
    RichonlineTerminalCoordinator(Storage& storage,RichonlineTerminalContext context);
    void bind_earned_cash(std::shared_ptr<const RichonlineGameLedger> ledger,std::uint8_t actor);
    // Reserve only after all startup validation; debit is independent of board cash.
    std::optional<GameEntryPledgeResult> prepare_start();
    void activate();
    std::optional<GameEntryPledgeResult> abort_start(const std::string& reason);
    // Explicit live-session release policy: before activation return only the
    // actual held pledge; after activation persist loss using this match's loss
    // reward policy. No result packets/outbox are created after leave ACK4006.
    // A result already committed by bankrupt() is preserved, never made a loss.
    RichonlineTerminalAbandonResult abandon(const std::string& reason);
    // Combat/NPC cash has already committed. This method never debits it again.
    RichonlineTerminalStep bankrupt(std::span<const std::int8_t> actors);
    const RichonlineSettlementTransmission* next_transmission() const noexcept;
    // Read-only planner snapshot; no outbox checkpoint before actual sends.
    std::vector<Bytes> pending_game_messages() const;
    // Call only after successful whole send. The final message is lobby wire58,
    // which retains the room; wire57 removes the room and is not interchangeable.
    void confirm_sent(std::uint32_t sequence);
    RichonlineTerminalPhase phase() const noexcept { return phase_; }
    const RichonlineTerminalSnapshot& roster() const noexcept { return context_.roster; }
private:
    void freeze_achievement();
    Storage& storage_;
    RichonlineTerminalContext context_;
    RichonlineTerminalPhase phase_{RichonlineTerminalPhase::prepared};
    bool reserved_{};
    bool activated_{};
    bool settled_{};
    std::vector<RichonlineSettlementTransmission> transmissions_;
    std::size_t next_{};
    std::shared_ptr<const RichonlineGameLedger> income_ledger_;
    std::uint8_t income_actor_{};
};
}
