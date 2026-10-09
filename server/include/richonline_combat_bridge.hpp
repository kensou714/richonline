#pragma once
#include "richonline_boss_property.hpp"
#include "richonline_npc_spawn.hpp"
#include "richonline_timed_bomb.hpp"

namespace richnet {
// Supplied explicitly from the room's current capabilities/status authority.
// The bridge does not invent hospital, vehicle, active or building-buff stores.
struct RichonlineCombatCapabilities {
    bool active,in_hospital,in_prison,mine_immune_vehicle,attack_modifiers_enabled;
};
struct RichonlineCombatActorRef {
    std::uint8_t slot;
    std::int16_t position;
    RichonlineActorStatus* status;
    RichonlineCombatCapabilities capabilities;
    bool* active=nullptr;
    std::optional<std::uint32_t>* attack_building_source=nullptr;
    std::optional<std::uint32_t>* defense_building_source=nullptr;
};
struct RichonlineCombatBridgeResult {
    std::vector<Bytes> packets;
    std::vector<std::uint8_t> bankrupt_actors;
};
// All calls run under the serialized room executor. ActorRefs live only during
// the call; every snapshot is built from the same ledger/cards/ground/property.
// No private actor status, money, inventory or ownership authority is retained.
class RichonlineCombatBridge final {
public:
    RichonlineCombatBridge(std::uint16_t game,std::shared_ptr<RichonlineGameLedger>,
        std::shared_ptr<RichonlineBossCards> human_cards,std::shared_ptr<RichonlineGroundObjects>,
        std::shared_ptr<RichonlineBossProperty>,RichonlineCombatWorld,RichonlineBossCombatPolicy);
    RichonlineCombatBridgeResult boss_turn(std::span<const RichonlineCombatActorRef>,std::uint8_t boss,
        const RichonlineBossAttackRandomness&);
    RichonlineCombatBridgeResult human_card(std::span<const RichonlineCombatActorRef>,
        const RichonlineTargetCardRequest&,std::uint16_t expected_calendar);
    RichonlineCombatBridgeResult finish_round(std::span<const RichonlineCombatActorRef>,std::uint64_t day);
    bool has_mine(std::int16_t position) const;
    RichonlineCombatBridgeResult stepped_mine(std::span<const RichonlineCombatActorRef>,std::int16_t root);
    RichonlineCombatBridgeResult timed_bomb_card(std::span<const RichonlineCombatActorRef>,
        std::uint8_t action_actor,const RichonlineTimedBombRequest110&,std::uint16_t expected_calendar,
        const RichonlineTimedBombRules&,const RichonlineTimedBombEligibility&,std::uint8_t envelope_opaque7);
    // Explosion requires the actual0012 acknowledgement. Non-exploding route
    // steps must have no acknowledgement. The serialized room owns route progress.
    RichonlineCombatBridgeResult timed_bomb_step(std::span<const RichonlineCombatActorRef>,
        const RichonlineTimedBombStepContext&,const std::optional<RichonlineMoveCountdown12>&,
        std::uint16_t expected_calendar,RichonlineTimedBombContinuationPolicy);
    class PreparedTimedBombSegment final {
    public:
        const RichonlineTimedBombSegmentPlan& plan() const;
        bool committed() const noexcept;
    private:
        struct Data;
        std::shared_ptr<Data> data_;
        explicit PreparedTimedBombSegment(std::shared_ptr<Data>);
        friend class RichonlineCombatBridge;
    };
    // refs retain their original authoritative positions through commit. The
    // owner updates route/position only after this atomic shared-state commit.
    PreparedTimedBombSegment prepare_timed_bomb_segment(std::span<const RichonlineCombatActorRef>,
        std::uint8_t moving_actor,std::span<const RichonlineTimedBombStepContext>,
        std::uint16_t expected_calendar,RichonlineTimedBombContinuationPolicy) const;
    RichonlineCombatBridgeResult commit_timed_bomb_segment(std::span<const RichonlineCombatActorRef>,
        PreparedTimedBombSegment&,const std::optional<RichonlineMoveCountdown12>&);
private:
    std::uint16_t game_;
    std::shared_ptr<RichonlineGameLedger> ledger_;
    std::shared_ptr<RichonlineBossCards> cards_;
    std::shared_ptr<RichonlineGroundObjects> ground_;
    std::shared_ptr<RichonlineBossProperty> property_;
    RichonlineCombatWorld world_;
    RichonlineBossCombatPolicy policy_;
    std::uint64_t revision_=0;
    std::optional<std::uint64_t> last_day_;
    struct Snapshot {
        RichonlineCombatSessionView combat;
        RichonlineGroundSnapshot ground;
        RichonlineBossProperty::CombatSnapshot property;
    };
    Snapshot snapshot(std::span<const RichonlineCombatActorRef>) const;
    RichonlineCombatBridgeResult apply(std::span<const RichonlineCombatActorRef>,
        const Snapshot&,RichonlineCombatTurnPlan);
};
}
