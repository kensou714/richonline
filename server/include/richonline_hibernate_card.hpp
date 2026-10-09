#pragma once
#include "richonline_card_protection.hpp"

namespace richnet {
struct RichonlineHibernateRequest {
    std::uint16_t calendar;
    std::int8_t inventory_slot, inventory_bank;
};
struct RichonlineHibernateRules {
    std::uint8_t frozen_turns;
    static RichonlineHibernateRules parse(std::string_view gvalue);
    static RichonlineHibernateRules load(const std::filesystem::path& root);
};
struct RichonlineHibernateActor {
    RichonlineProtectionInventory inventory;
    RichonlineActorStatus status;
    bool present;
    // Explicit projections of NEW651570/7CF340 predicates; do not infer from names.
    std::int8_t raw1493=-1, raw1494=-1, raw1495=-1, raw1497=-1;
    std::array<std::uint8_t,8> relations1472;
    bool operator==(const RichonlineHibernateActor&) const = default;
};
struct RichonlineHibernateSnapshot {
    std::uint16_t game_id, calendar;
    std::int8_t active_actor;
    bool roll_phase, active_actor_can_act;
    std::array<RichonlineHibernateActor,8> actors;
    bool operator==(const RichonlineHibernateSnapshot&) const = default;
};
enum class RichonlineHibernateEffect { ineligible, requester, status_immunity, passive_protection, frozen };
enum class RichonlineHibernateContinuation { requester_continues_action };
struct RichonlineHibernatePlan {
    RichonlineHibernateSnapshot before, after;
    std::array<RichonlineHibernateEffect,8> effects;
    std::array<std::optional<RichonlineProtectionCardSource>,8> consumed_protection;
    Bytes response40f4;
    RichonlineHibernateContinuation continuation=RichonlineHibernateContinuation::requester_continues_action;
};
RichonlineHibernateRequest decode_richonline_hibernate164(View);
Bytes encode_richonline_hibernate40f4(std::uint16_t game_id,const RichonlineHibernateRequest&);
RichonlineHibernatePlan plan_richonline_hibernate(const RichonlineHibernateRequest&,
    std::uint16_t expected_game_id,std::int8_t requesting_actor,std::string_view map,
    const RichonlineChanceResources&,const RichonlineHibernateRules&,const RichonlineHibernateSnapshot&);
// Call under the room lock. The comparison precedes every mutation.
void commit_richonline_hibernate(RichonlineHibernateSnapshot&,const RichonlineHibernatePlan&);
// NEW7C0C50 normal turn entry decrements before the later frozen branch.
// Call once on new-turn entry, never on phase4 reentry. True means queue the
// 1800ms local presentation and advance without movement/0011.
bool richonline_hibernate_begin_turn(RichonlineActorStatus&);
}
