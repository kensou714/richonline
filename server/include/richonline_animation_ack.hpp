#pragma once

#include "codec.hpp"
#include <bitset>
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
// Wire21 cannot distinguish animations with the same counter. Consequently each
// 16-bit counter may be registered only once in this instance, even after wrap.
// A fresh local epoch/sequence cannot authenticate a reused wire counter.
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
    std::optional<std::uint64_t> last_turn_;
    std::bitset<65536> registered_,completed_;
    bool closed_=false;
};
}
