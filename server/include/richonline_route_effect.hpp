#pragma once

#include "codec.hpp"

namespace richnet {
// Pure NEW 7F5D90 movement-step effects. The session owns dynamics, statuses,
// route geometry, money and phase transitions; this planner commits none.
enum class RichonlineRouteInvestmentGate { skip,await_choice,complete_collection };
enum class RichonlineRouteStepKind { walking,ordinary_endpoint,roadblock_stop,
    timed_bomb_stop,bank_pause,investment_pause };
// Owner1492 is signed; -1 means there is no attributed player.
struct RichonlineRouteTimedBomb { std::uint8_t steps_left; std::int8_t owner; };
struct RichonlineRouteStepContext {
    std::int16_t position;
    // One-based number of the just-completed step, matching actor1456.
    std::uint8_t completed_step,movement_budget,available_route_steps;
    std::int8_t static_type,dynamic_type;
    bool actor552;
    bool possession7,actor1499,game83830_active,bank_closed;
    std::optional<RichonlineRouteTimedBomb> timed_bomb;
    RichonlineRouteInvestmentGate investment;
};
struct RichonlineRouteStepEffect {
    RichonlineRouteStepKind kind;
    std::optional<std::uint16_t> expected_request;
    std::int16_t reported_position;
    std::uint8_t movement_budget_after;
    std::optional<RichonlineRouteTimedBomb> timed_bomb_after;
    std::optional<std::int8_t> exploding_bomb_owner;
    std::optional<std::int8_t> removed_dynamic;
    bool advance_route_progress;
    bool automatic_investment_reward;
    // Nonzero countdown can transfer to a same-position actor before dynamic
    // processing. Caller must resolve NEW60C197's collision instead of silently
    // treating this as the final authoritative countdown for later steps.
    bool check_timed_bomb_transfer;
};
RichonlineRouteStepEffect plan_richonline_route_step_effect(const RichonlineRouteStepContext&);
}
