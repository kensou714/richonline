#pragma once

#include "richonline_game_ledger.hpp"
#include "richonline_raw_authority.hpp"
#include "richonline_route.hpp"

namespace richnet {
struct RichonlineNpcAuraRules {
    std::int32_t amount;
    std::int32_t radius;
    static RichonlineNpcAuraRules load(const std::filesystem::path& root);
};
struct RichonlineNpcAuraEffect {
    std::int32_t strength1740;
    float multiplier1744;
};
struct RichonlineNpcAuraContext {
    std::uint32_t mode;
    std::uint8_t active_actor,boss_slot;
    std::optional<std::int8_t> possession;
    // The source's god effect is separate from attack/damage multipliers.
    // Absence means unknown authority, not an implicit unstrengthened god.
    std::optional<RichonlineNpcAuraEffect> effect;
};
struct RichonlineNpcAuraActor {
    std::uint8_t slot;
    std::int16_t position;
    bool active;
    RichonlineRawActorState raw;
    RichonlineGameFundsSnapshot funds;
};
struct RichonlineNpcAuraPlan {
    std::int32_t amount;
    std::vector<RichonlineGameFundsUpdate> updates;
    std::vector<std::uint8_t> bankrupt_actors;
};
// NEW7C0C50 -> 7CEA20, after the active actor's possession expiry. Mode3
// excludes the Boss TARGET even when the Boss is the source. The square uses
// every map cell, not road distance. No additional network packet is emitted:
// 4010 starts the client's local6060/606E chain.
RichonlineNpcAuraPlan plan_richonline_npc_aura(const RichonlineRoadTopology&,
    const RichonlineNpcAuraRules&,const RichonlineNpcAuraContext&,
    std::span<const RichonlineNpcAuraActor>);
} // namespace richnet
