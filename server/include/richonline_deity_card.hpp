#pragma once
#include "richonline_actor_status.hpp"
#include "richonline_boss_cards.hpp"

namespace richnet {
enum class RichonlineDeityCard : std::uint16_t { summon1047=112, dismiss1048=113 };
struct RichonlineDeityCardRequest {
    RichonlineDeityCard kind;
    std::uint16_t calendar;
    std::int8_t slot,bank,target_actor;
    std::uint8_t unread7;
};
struct RichonlineDeityCardTarget {
    std::int8_t actor;
    bool active,in_target_selection;
    RichonlineActorStatus status;
};
struct RichonlineSummonedNpc {
    std::int16_t position;
    std::int8_t id;
    std::uint8_t affix_turns;
    bool present,visible;
    bool operator==(const RichonlineSummonedNpc&) const = default;
};
// The attachment confirmation is only one step. The owner must prepare the
// matching effect before committing; 0/1 subsequently send C2S34, 2/3 need a
// server result without an acknowledgement, and 7 has sleep-protection rules.
enum class RichonlineDeityCardContinuation {
    restore_action, await_money34, send_lost_cards4024, send_fortune4023, resolve_sleepwalking
};
struct RichonlineDeityCardPlan {
    Bytes response;
    RichonlineBossCards::PreparedConsumption consumption;
    RichonlineDeityCardTarget before,after;
    std::optional<RichonlineSummonedNpc> remove_ground_npc;
    std::uint8_t possession_turns;
    RichonlineDeityCardContinuation continuation;
};
RichonlineDeityCardRequest parse_richonline_deity_card(View);
RichonlineDeityCardPlan plan_richonline_deity_card(std::uint16_t game_id,
    const RichonlineDeityCardRequest&,std::uint16_t current_calendar,
    const RichonlineDeityCardTarget&,const std::optional<RichonlineSummonedNpc>&,
    const RichonlineBossCards&,std::uint8_t active_actor);
}
