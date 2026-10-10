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
    // Separate placement occupancy (for new ground mines) from actor combat
    // collision/targetability. The room supplies the independently-following
    // pet cell when one is present.
    bool placement_present=true;
    std::optional<std::int16_t> pet_position{};
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
        const RichonlineBossAttackRandomness&,const std::function<void(const std::string&)>& log={});
    RichonlineCombatBridgeResult human_card(std::span<const RichonlineCombatActorRef>,
        const RichonlineTargetCardRequest&,std::uint16_t expected_calendar,bool recover_refusal=false,
        const std::function<void(const std::string&)>& log={});
    class PreparedHumanAttack final {
    public:
        const std::vector<Bytes>& packets() const;
    private:
        struct Data;
        std::shared_ptr<Data> data_;
        explicit PreparedHumanAttack(std::shared_ptr<Data>);
        friend class RichonlineCombatBridge;
    };
    // Lua只能保留不透明计划。返回完整确认且验证成功之后，才提交整次战斗与扣卡。
    PreparedHumanAttack prepare_human_attack(std::span<const RichonlineCombatActorRef>,
        const RichonlineTargetCardRequest&,std::uint16_t expected_calendar,
        const RichonlineBossCards::PreparedConsumption&) const;
    PreparedHumanAttack prepare_timed_bomb_card(std::span<const RichonlineCombatActorRef>,
        std::uint8_t action_actor,const RichonlineTimedBombRequest110&,std::uint16_t expected_calendar,
        const RichonlineTimedBombRules&,const RichonlineTimedBombEligibility&,
        const RichonlineBossCards::PreparedConsumption&,std::uint8_t envelope_opaque7) const;
    RichonlineCombatBridgeResult commit_human_attack(std::span<const RichonlineCombatActorRef>,
        PreparedHumanAttack&,const std::function<void(const std::string&)>& log={});
    RichonlineCombatBridgeResult finish_round(std::span<const RichonlineCombatActorRef>,std::uint64_t day);
    RichonlineCombatBridgeResult missile_base_round(std::span<const RichonlineCombatActorRef>,std::uint64_t round,
        const std::function<std::size_t(std::size_t)>& random,const std::function<void(const std::string&)>& log);
    RichonlineCombatBridgeResult detonate_card(std::span<const RichonlineCombatActorRef>,std::uint8_t slot,
        const std::function<void(const std::string&)>& log);
    bool has_mine(std::int16_t position) const;
    RichonlineCombatBridgeResult stepped_mine(std::span<const RichonlineCombatActorRef>,std::int16_t root,
        bool notify_client=false);
    // Calls the pure continuation preflight only for a surviving victim, before
    // the shared ledger commit. Fatal landings proceed directly to settlement.
    RichonlineCombatBridgeResult fire_landing(std::span<const RichonlineCombatActorRef>,
        std::uint8_t victim,std::int16_t position,std::uint32_t npc26_damage,
        const std::function<void()>& continuation_preflight);
    RichonlineCombatBridgeResult poison_card(std::span<const RichonlineCombatActorRef>,
        const RichonlineResearchCardRequest&,const RichonlineResearchCardContext&,std::uint32_t& use_count,
        const RichonlinePoisonRules&,std::span<const RichonlinePoisonCell>,std::span<const RichonlineRawActorState>,
        std::span<std::array<std::uint8_t,8>> relations,bool recover_refusal=false,
        const std::function<void(const std::string&)>& log = {});
    RichonlineCombatBridgeResult timed_bomb_card(std::span<const RichonlineCombatActorRef>,
        std::uint8_t action_actor,const RichonlineTimedBombRequest110&,std::uint16_t expected_calendar,
        const RichonlineTimedBombRules&,const RichonlineTimedBombEligibility&,std::uint8_t envelope_opaque7,
        const std::function<void(const std::string&)>& log={});
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
        const Snapshot&,RichonlineCombatTurnPlan,const RichonlineBossProperty::PreparedMissileRound* missile_round=nullptr,
        const std::function<void(const std::string&)>& log={});
};
}
