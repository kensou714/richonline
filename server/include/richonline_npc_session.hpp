#pragma once
#include "richonline_npc.hpp"
#include "richonline_npc_spawn.hpp"
#include "richonline_deity_card.hpp"

namespace richnet {
enum class RichonlineNpcWait { none, roulette34, settlement };
struct RichonlineNpcSessionResult {
    std::vector<Bytes> messages;
    RichonlineNpcContinuation continuation;
    RichonlineNpcWait wait;
    bool sent_stop4013;
    std::optional<std::uint8_t> bankrupt_actor{};
};
struct RichonlineNpcBadluckPolicy {
    std::uint8_t resource_affix_turns;
    std::string selection_policy_name;
    std::function<std::array<std::int8_t,4>(const RichonlineChanceInventory&)> lost_slots;
};
struct RichonlineNpcSleepPolicy {
    std::uint8_t resource_affix_turns;
    std::string protection_policy_name;
    // This inventory belongs to actor: synthetic participants receive an empty
    // main inventory, never the local player's card manager. The callback must
    // enforce Prop1071 CARD/map activation and explicit equipment availability.
    std::function<RichonlineSleepProtection(std::uint8_t,const RichonlineChanceInventory&,
        const RichonlineActorStatus&)> protection;
};
struct RichonlineNpcSessionPolicy {
    RichonlineNpcSpawnPolicy spawn;
    std::uint32_t spawn_seed;
    std::array<std::int16_t,2> fortune_cards;
    // These are the actual client actor+44 values, not guessed lobby identities.
    std::array<std::int32_t,2> actor44;
    // Read with load_richonline_npc_affix(root,0/1); fortune uses NpcRules.
    std::array<std::uint8_t,2> money_affix_turns;
    // Nonnegative signed16 result under an explicitly named emulator policy.
    std::string money_policy_name;
    std::function<std::int16_t(std::uint8_t,std::int8_t,
        const std::array<RichonlineGameFundsSnapshot,2>&)> money_amount;
    std::optional<RichonlineNpcBadluckPolicy> badluck{};
    std::optional<RichonlineTicketChestRules> ticket_chest{};
    std::optional<RichonlineNpcSleepPolicy> sleep_deity{};
    // Temple6051 only: these gods remain unavailable to ground/card dispatch.
    std::optional<std::array<std::uint8_t,2>> temple_aura_affix{};
};

// One serialized room executor owns this coordinator, the ground container,
// ledger and card manager. ActorStatus is always borrowed from authoritative
// Turns state. Only possession duration/own-turn identity is mirrored here.
class RichonlineNpcSession final {
public:
    RichonlineNpcSession(std::uint16_t game,std::string map,
        RichonlineNpcRules,std::shared_ptr<const RichonlineChanceResources>,
        std::shared_ptr<const RichonlineChanceEventTable>,std::shared_ptr<RichonlineGameLedger>,
        std::shared_ptr<RichonlineBossCards>,std::shared_ptr<RichonlineGroundObjects>,
        RichonlineNpcSessionPolicy);
    RichonlineNpcSpawnResult initial();
    RichonlineNpcSpawnResult finish_round(std::uint64_t complete_round);
    RichonlinePossessionTick actor_begin(std::uint8_t actor,std::uint64_t own_turn,
        RichonlineActorStatus& authoritative_status);
    class PreparedStatusChange {
    public:
        const RichonlineActorStatus& after() const noexcept {return after_status_;}
    private:
        PreparedStatusChange()=default;
        const RichonlineNpcSession* owner_=nullptr;
        std::uint8_t actor_=0;
        std::uint64_t generation_=0;
        RichonlineActorStatus before_status_{},after_status_{};
        RichonlinePossessionClock before_clock_{},after_clock_{};
        bool committed_=false;
        bool requires_idle_=false;
        friend class RichonlineNpcSession;
    };
    // External status/card/combat planners must prepare against the current
    // borrowed status before committing it. This hook preserves an existing
    // possession duration or detaches it; new attachment belongs to NPC hooks.
    PreparedStatusChange prepare_status_change(std::uint8_t actor,
        const RichonlineActorStatus& before,const RichonlineActorStatus& after) const;
    PreparedStatusChange prepare_temple_change(std::uint8_t actor,
        const RichonlineTemplePossessionChange&) const;
    bool matches_status_change(const PreparedStatusChange&,const RichonlineActorStatus&) const noexcept;
    bool commit_status_change(PreparedStatusChange&,RichonlineActorStatus&) noexcept;
    void detach(std::uint8_t actor,RichonlineActorStatus& authoritative_status);
    // A handled ground event continues phase1; it is NOT a complete landing.
    // No matching implemented NPC leaves every shared object unchanged.
    std::optional<RichonlineNpcSessionResult> landing(const RichonlineLandingContext&,
        std::uint16_t calendar,RichonlineActorStatus& authoritative_status,
        const std::function<void(const RichonlineLandingContext&)>& preflight = {});
    RichonlineNpcSessionResult handle(View request,std::uint8_t actor,
        RichonlineActorStatus& authoritative_status);
    // The room may resolve its authoritative pending roulette at a configured
    // timeout without manufacturing an inbound client packet.
    RichonlineNpcSessionResult resolve_roulette(std::uint8_t actor,
        RichonlineActorStatus& authoritative_status);
    RichonlineNpcSessionResult fortune_card(View request,const RichonlineLandingContext&,
        RichonlineActorStatus& authoritative_status);
    RichonlineNpcSessionResult wealth_card(View request,const RichonlineLandingContext&,
        RichonlineActorStatus& authoritative_status);
    // Candidate positions are an explicit server selection policy: C2S112
    // does not transmit the client's viewport or a chosen ground NPC.
    // The request's target byte is an actor, never an NPC ID.
    RichonlineNpcSessionResult deity_card(View request,const RichonlineLandingContext& source,
        std::uint16_t current_calendar,RichonlineActorStatus& target_status,bool target_selectable,
        std::span<const std::int16_t> candidate_ground_positions,const RichonlineRouteChooser&);
    bool awaiting_roulette() const noexcept;
    bool awaiting_settlement() const noexcept;
private:
    struct PendingMoney {
        std::uint8_t actor;
        std::uint16_t calendar;
        std::int8_t npc;
        RichonlineDeityMoneyOrigin origin;
        bool settlement=false;
    };
    std::uint16_t game_;
    std::string map_;
    RichonlineNpcRules rules_;
    std::shared_ptr<const RichonlineChanceResources> resources_;
    std::shared_ptr<const RichonlineChanceEventTable> events_;
    std::shared_ptr<RichonlineGameLedger> ledger_;
    std::shared_ptr<RichonlineBossCards> cards_;
    std::shared_ptr<RichonlineGroundObjects> ground_;
    RichonlineNpcSessionPolicy policy_;
    RichonlineNpcSpawner spawner_;
    std::array<RichonlinePossessionClock,2> clocks_{};
    std::array<std::uint64_t,2> clock_generations_{};
    std::optional<PendingMoney> pending_;
    bool initialized_=false;
    void check_actor(std::uint8_t,const RichonlineActorStatus&) const;
    void admit_clock_change(std::uint8_t) const;
    bool supported_npc(std::int8_t) const noexcept;
    std::uint8_t affix_turns(std::int8_t) const;
    std::optional<RichonlineNpcSessionResult> chest_landing(const RichonlineLandingContext&,
        const RichonlineGroundSnapshot&,const RichonlineGroundObject&);
};
}
