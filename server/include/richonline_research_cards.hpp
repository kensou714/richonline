#pragma once
#include "richonline_ground_card.hpp"
#include "richonline_game_ledger.hpp"
#include <functional>

namespace richnet {
class RichonlineRoadTopology;
struct RichonlinePoisonRules {
    std::uint8_t range;
    std::uint32_t base_damage;
    static RichonlinePoisonRules load(const std::filesystem::path& root);
};
enum class RichonlineResearchCard : std::uint16_t { ice1181=1181,poison1182=1182,fire1183=1183 };
struct RichonlineResearchCardRequest {
    RichonlineResearchCard card;
    std::uint16_t calendar;
    std::int8_t slot,bank;
    // 156 has constructor byte6=1 and opaque uninitialized byte7, not a tile.
    std::optional<std::int16_t> position;
    std::uint8_t poison_activation,opaque7;
};
RichonlineResearchCardRequest decode_richonline_research_card(View);
// Success consumes inventory locally. Refusal must never use this packet.
Bytes encode_richonline_research_card_success(std::uint16_t game,const RichonlineResearchCardRequest&);
struct RichonlineResearchCardContext {
    std::uint16_t game,calendar;
    std::int8_t actor,requesting_actor;
    bool roll_phase,can_act;
};
struct RichonlineResearchTrapCell {
    bool walkable,actor_occupied;
    std::int8_t static_type;
};
struct RichonlineResearchTrapMap {
    std::uint16_t width,height;
    bool center_visible;
    // Authenticated map adapter; invoked only for coordinates in map bounds.
    std::function<RichonlineResearchTrapCell(std::int16_t)> cell;
    // NEW 40ED makes BOSS-marked actors owner -1. Session supplies that predicate.
    std::int8_t fire_owner;
};
struct RichonlineResearchTrapRules {
    std::uint8_t freeze_timer,fire_radius,fire_rounds;
    static RichonlineResearchTrapRules parse(std::string_view decoded_gvalue);
    static RichonlineResearchTrapRules load(const std::filesystem::path& root);
};
struct RichonlineFireTrapRules {
    RichonlineResearchTrapRules traps;
    std::uint32_t npc26_damage;
    static RichonlineFireTrapRules load(const std::filesystem::path& root);
};
struct RichonlineResearchTrapPlan {
    RichonlineGroundSnapshot expected_ground;
    RichonlineGroundMap after_ground;
    RichonlineChanceInventory expected_inventory,after_inventory;
    Bytes success;
};
RichonlineResearchTrapPlan plan_richonline_research_trap(const RichonlineResearchCardRequest&,
    const RichonlineResearchCardContext&,const RichonlineResearchTrapMap&,
    const RichonlineResearchTrapRules&,const RichonlineChanceInventory&,const RichonlineGroundSnapshot&);
struct RichonlineIceTrapLanding {
    RichonlineGroundSnapshot expected_ground;
    RichonlineGroundMap after_ground;
    RichonlineActorStatus expected_status,after_status;
    bool protected_from_freeze;
};
// 7C3220 consumes the trap even when actor1696 protects against freezing.
// No extra network packet: the accepted landing packet performs this locally.
RichonlineIceTrapLanding plan_richonline_ice_trap_landing(std::int16_t position,
    const RichonlineGroundSnapshot&,const RichonlineActorStatus&,const RichonlineResearchTrapRules&);
struct RichonlineFireTrapTick {
    RichonlineGroundSnapshot expected_ground;
    RichonlineGroundMap after_ground;
};
// Invoke once at the verified NEW7C0C50 active-status clock. Owner's turn ticks
// owned flames; neutral/inactive-owner flames tick only at the round anchor.
RichonlineFireTrapTick plan_richonline_fire_trap_tick(const RichonlineGroundSnapshot&,
    std::uint8_t current_actor,bool round_anchor,std::span<const bool> active_actors);
RichonlineGameFundsUpdate plan_richonline_fire_trap_damage(std::uint8_t victim,
    const RichonlineGameFundsSnapshot&,std::uint32_t resolved_npc26_damage);
struct RichonlinePoisonCell { std::int16_t position; std::uint8_t attenuation_layer; };
using RichonlinePoisonStep=std::function<std::optional<std::int16_t>(std::int16_t,std::uint8_t)>;
// Includes center layer0; first cardinal step is also layer0, then1,2.
std::vector<RichonlinePoisonCell> richonline_poison_footprint(std::int16_t origin,
    std::uint8_t range,const RichonlinePoisonStep&);
// NEW rays cross nonroads; only the eventual victim cell must be walkable.
std::vector<RichonlinePoisonCell> richonline_poison_map_footprint(const RichonlineRoadTopology&,
    std::int16_t origin,std::uint8_t range);
struct RichonlinePoisonVictim {
    std::uint8_t actor;
    std::int16_t position;
    bool active,hospital,prison,excluded1497;
    RichonlineGameFundsSnapshot funds;
    // Resolved by the shared 7CE420 combat formula, including all modifiers.
    std::uint32_t adjusted_damage;
};
struct RichonlinePoisonPlan {
    RichonlineChanceInventory expected_inventory,after_inventory;
    std::uint32_t expected_use_count,after_use_count;
    std::vector<RichonlineGameFundsUpdate> funds;
    std::vector<std::uint8_t> bankrupt;
    Bytes success;
};
// Pure preparation. Caller atomically commits inventory, every funds snapshot
// and the current action's use counter before publishing success. No cash-delta wire.
RichonlinePoisonPlan plan_richonline_poison_card(const RichonlineResearchCardRequest&,
    const RichonlineResearchCardContext&,const RichonlineChanceInventory&,
    std::uint32_t action_use_count,std::uint32_t prop1182_base_damage,
    std::span<const RichonlinePoisonCell>,std::span<const RichonlinePoisonVictim>);
} // namespace richnet
