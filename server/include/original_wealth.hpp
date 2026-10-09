#pragma once
#include "original_board.hpp"
#include "original_god_wire.hpp"
#include <optional>

namespace richnet {
enum class OriginalWealthOrigin { landing, card, property };
enum class OriginalWealthContinuation { landing, card, property, bankruptcy };
struct OriginalWealthPlayer {
    OriginalFunds funds;
    std::int32_t team;
    bool alive;
    std::int8_t god;
};
struct OriginalWealthPending {
    std::uint16_t context;
    std::uint8_t actor;
    std::int8_t god;
    OriginalWealthOrigin origin;
};
struct OriginalWealthSnapshot {
    std::uint16_t context;
    std::uint8_t actor;
    std::vector<OriginalWealthPlayer> players;
};
struct OriginalWealthOutcome {
    std::vector<OriginalWealthPlayer> players;
    std::vector<std::uint8_t> bankrupt_slots;
    std::int16_t amount;
    bool bankruptcy_wait;
    OriginalWealthContinuation continuation;
};
class OriginalWealthSettlement final {
public:
    void begin(OriginalWealthPending pending);
    OriginalWealthOutcome resolve(const OriginalWealthChoice& request,
        const OriginalWealthSnapshot& snapshot, std::int32_t amount);
    OriginalWealthContinuation finish_bankruptcy(std::uint16_t context);
    const std::optional<OriginalWealthPending>& pending() const noexcept { return pending_; }
    bool awaiting_bankruptcy() const noexcept { return awaiting_bankruptcy_; }
private:
    std::optional<OriginalWealthPending> pending_;
    bool awaiting_bankruptcy_ = false;
};
}
