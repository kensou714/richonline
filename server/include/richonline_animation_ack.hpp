#pragma once

#include "codec.hpp"
#include <chrono>

namespace richnet {
struct RichonlineAnimationAck21 { std::uint16_t calendar_counter; };
RichonlineAnimationAck21 decode_richonline_animation_ack21(View plain);

enum class RichonlineAckAnimation : std::uint8_t { type6=6, type10=10, type12=12 };
struct RichonlineAnimationAckGates {
    std::uint8_t actor;
    std::uint8_t local_actor;
    bool player552;
    bool player1488_is7;
    bool player1499;
};
struct RichonlineAnimationAckContext {
    // Captured by the owner when dispatching input, never decoded from wire21.
    std::uint64_t event_token;
    std::uint64_t turn_sequence;
    RichonlineAnimationAckGates gates;
};
struct RichonlineAnimationAckTransition {
    // Opaque owner-issued continuation identity; this module never advances gameplay.
    std::uint64_t token;
    std::uint64_t turn_sequence;
    std::uint16_t calendar_counter;
    RichonlineAckAnimation animation;
    bool type6_mode1;
    RichonlineAnimationAckGates gates;
    std::chrono::steady_clock::time_point deadline;
};
enum class RichonlineAnimationAckDisposition { completed, duplicate, expired };
struct RichonlineAnimationAckResult {
    RichonlineAnimationAckDisposition disposition;
    // Present exactly once, only for an accepted, live transition.
    std::optional<RichonlineAnimationAckTransition> transition;
};

// One instance per authenticated connection/game lifetime, never shared across games.
// The caller registers only a proven ACK-producing transition, before exposing it
// to the client, and supplies authoritative current context on receive.
// Experimental, not wired into Turns. Wire21 cannot distinguish repeated bytes
// for two same-counter events. The owner must serialize triggers/completions on
// one ordered connection, and establish that the client emits one ACK per event.
// event_token protects stale server callbacks; it does NOT authenticate wire21.
class RichonlineAnimationAck final {
public:
    using Clock=std::chrono::steady_clock;
    void begin(const RichonlineAnimationAckTransition& transition,Clock::time_point now);
    RichonlineAnimationAckResult accept(View plain,const RichonlineAnimationAckContext& context,
        Clock::time_point now);
    std::optional<RichonlineAnimationAckTransition> expire(Clock::time_point now);
    std::optional<RichonlineAnimationAckTransition> cancel();
    void close() noexcept;
    bool pending() const noexcept { return pending_.has_value(); }
    bool closed() const noexcept { return closed_; }
private:
    std::optional<RichonlineAnimationAckTransition> pending_;
    struct Retired {
        RichonlineAnimationAckTransition transition;
        RichonlineAnimationAckDisposition disposition;
    };
    std::optional<Retired> retired_;
    std::optional<std::uint64_t> last_turn_;
    std::uint64_t last_token_=0;
    bool closed_=false;
};
}
