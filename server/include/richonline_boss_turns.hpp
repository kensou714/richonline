#pragma once

// 新版双角色 BOSS 回合协调：以落点结果决定等待事件、完成落点或结束对局。

#include "richonline_boss_startup.hpp"
#include "richonline_game_startup.hpp"
#include "richonline_movement_wire.hpp"
#include "richonline_route.hpp"
#include "richonline_actor_status.hpp"
#include "richonline_game_payment.hpp"
#include "richonline_hibernate_card.hpp"
#include "richonline_raw_authority.hpp"
#include "richonline_npc_aura.hpp"
#include <chrono>
#include "lua_server.hpp"

namespace richnet {
class RichonlineBossCards;
class RichonlineBossProperty;
class RichonlineGameBank;
class RichonlineGameLedger;
class RichonlineNpcSession;
class RichonlineCombatBridge;
class RichonlineGroundObjects;
struct RichonlineBossAttackRandomness;
struct RichonlineCombatCapabilities;
struct RichonlineMotionCardRules;
struct RichonlineTimedBombRules;
struct RichonlineTimedBombStepContext;
struct RichonlineResearchTrapRules;
struct RichonlineFireTrapRules;
struct RichonlinePoisonRules;
struct RichonlineHibernateTurnPolicy {
    std::shared_ptr<const RichonlineChanceResources> resources;
    RichonlineHibernateRules rules;
    std::function<RichonlineRawActorState(std::uint8_t)> raw_actor;
};
struct RichonlinePortalLandingPlan;
struct RichonlineTimedBombTurnPolicy {
    std::shared_ptr<const RichonlineTimedBombRules> resources;
    std::uint8_t response_opaque7;
    // The room supplies actor552, game83830 and all existing actors' raw
    // eligibility sentinels from its actual authority. These are not inferred
    // from possession, sleepwalking, or a default all-clear status.
    std::function<RichonlineTimedBombStepContext(std::uint8_t,std::int16_t)> step_context;
};
struct RichonlineLandingContext {
    std::uint8_t actor_slot;
    std::int16_t position;
    std::int8_t static_type;
    std::int16_t property_ref;
    std::uint32_t game_mode = 0;
    bool synthetic_actor = false;
    std::uint8_t road_degree = 0;
    bool occupied_by_other_actor = false;
    RichonlineActorStatus actor_status{};
    // Physical occupancy remains observable. Only a proven no-transfer pair
    // can continue without an additional collision inventory transaction.
    bool collision_resolved=false;
};
enum class RichonlineLandingProgress { await_event, complete, finished };
struct RichonlineLandingStatusChange {
    RichonlineActorStatus expected,updated;
};
struct RichonlineTemplePossessionChange {
    RichonlineActorStatus expected;
    bool extend;
    std::int32_t days;
    std::uint8_t maximum;
    std::optional<std::int8_t> summon{};
    std::int32_t strength=0;
};
struct RichonlineLandingResult {
    std::vector<Bytes> messages;
    RichonlineLandingProgress progress;
    // await_event 时记录下一条预期动作；由回合协调层控制后续请求分派。
    std::optional<std::uint16_t> pending_opcode = {};
    std::optional<RichonlineLandingStatusChange> status_change{};
    std::optional<RichonlineTemplePossessionChange> temple_change{};
};
enum class RichonlineTerminalReason { npc_money, boss_attack, human_attack, mine_day, stepped_mine, timed_bomb, npc_aura, fire_trap, poison_card, month_limit, missile_base };
struct RichonlineTurnTerminalContext {
    std::vector<std::uint8_t> bankrupt_actors;
    RichonlineTerminalReason reason;
    std::uint32_t mode;
    std::uint8_t current_actor;
    std::uint16_t calendar_counter;
    std::uint64_t turn_sequence;
};
struct RichonlineTurnTerminalResult {
    std::vector<Bytes> messages;
    bool closed;
};
struct RichonlineBossTurnRules {
    std::uint8_t opaque_turn7;
    std::array<std::int8_t,2> inactive_ui_dice;
    RichonlineRouteWirePolicy route_wire;
    RichonlineRouteChooser random;
    std::function<RichonlineLandingResult(const RichonlineLandingContext&)> landed;
    std::function<RichonlineLandingResult(View)> event;
    std::shared_ptr<RichonlineBossCards> cards{};
    GameLogSink log{};
    std::function<std::optional<RichonlineLandingResult>()> poll{};
    std::function<std::chrono::steady_clock::time_point()> now = [] { return std::chrono::steady_clock::now(); };
    // Bank admission envelopes and initial deposit knowledge must be supplied explicitly.
    std::shared_ptr<RichonlineGameBank> bank{};
    std::shared_ptr<RichonlineGameLedger> ledger{};
    std::shared_ptr<const RichonlineMotionCardRules> motion_cards{};
    std::shared_ptr<RichonlineGamePayment> payment{};
    std::string payment_operation_prefix{};
    RichonlinePaidDiceEquipment payment_equipment{false,false};
    // 读取4010进入时的现金计算本回合回血；客户端已排6060，服务端只镜像账本。
    std::function<std::uint32_t(std::uint8_t,std::uint32_t)> equipment_healing{};
    std::function<std::optional<RichonlineLandingResult>(const RichonlineLandingContext&)> chance_landing{};
    // The room supplies map pairs or random-road candidates and scripted state.
    // A portal tile without this capability cannot be silently treated as an
    // ordinary landing or as an unconditional teleport.
    std::function<std::optional<RichonlinePortalLandingPlan>(const RichonlineLandingContext&)> portal_landing{};
    // Effective normal BOSS dice count from the selected BossWar stage; human
    // vehicle/dice-count equipment is not inferred from this stage field.
    std::uint8_t boss_dice_count=1;
    std::shared_ptr<RichonlineNpcSession> npcs{};
    // Pure validation of the shared landing continuation, before an NPC can
    // commit ground, inventory, possession or money changes.
    std::function<void(const RichonlineLandingContext&)> npc_landing_preflight{};
    // Explicit server recovery policy, not a recovered client countdown.
    std::chrono::milliseconds npc_roulette_timeout{30000};
    // NEW654780 checks viewport locally but sends no camera or god position.
    // This named server-policy boundary supplies eligible ground candidates;
    // it does not assert synchronization with the client's camera rectangle.
    std::function<std::vector<std::int16_t>(const RichonlineLandingContext&)> npc_summon_candidates{};
    std::shared_ptr<RichonlineCombatBridge> combat{};
    std::function<RichonlineBossAttackRandomness()> combat_random{};
    // Active is always overwritten from the turn owner's authoritative array.
    std::function<RichonlineCombatCapabilities(std::uint8_t,const RichonlineActorStatus&)> combat_capabilities{};
    std::function<RichonlineTurnTerminalResult(const RichonlineTurnTerminalContext&)> terminal{};
    // A controlled local actor still sends the ordinary0010 parameter0. If
    // that client timer never fires, recover once with the same ordinary4011.
    // This duration is explicit server policy, not a recovered client timer.
    std::chrono::milliseconds controlled_roll_timeout{30000};
    std::shared_ptr<const RichonlineTimedBombTurnPolicy> timed_bombs{};
    std::shared_ptr<RichonlineGroundObjects> ground{};
    // Explicit server visibility policy; NEW sends no camera rectangle.
    std::function<bool(std::uint8_t,std::int16_t,std::int16_t)> ground_card_visible{};
    std::shared_ptr<const RichonlineHibernateTurnPolicy> hibernate{};
    std::function<void(std::uint8_t)> research_turn_started{};
    std::optional<RichonlineNpcAuraRules> npc_aura{};
    std::function<RichonlineRawActorState(std::uint8_t)> npc_aura_raw_actor{};
    // Enables only1181/NPC25; fire and poison require separate closed authority.
    std::shared_ptr<const RichonlineResearchTrapRules> ice_traps{};
    std::shared_ptr<const RichonlineFireTrapRules> fire_traps{};
    std::shared_ptr<const RichonlinePoisonRules> poison{};
    std::function<RichonlineRawActorState(std::uint8_t)> poison_raw_actor{};
    std::shared_ptr<RichonlineBossProperty> property{};
    std::shared_ptr<RichonlineRawAuthority> raw_authority{};
    std::uint8_t jail_days=3,alliance_days=6;
    // NEW64F2A0 stores room months*30 in a BYTE; zero disables expiry.
    std::uint8_t month_limit_days=0;
    // Feast.kpd (2004-2034), thirteen ordered month/day pairs per year.
    std::array<std::array<std::array<std::uint8_t,2>,13>,31> feast_dates{};
    // NEW actor+152 comes from profile equipment slot2; absence is unknown.
    std::optional<bool> human_purchase_half_price{};
    std::shared_ptr<LuaServer> script{};
    std::string script_map{};
    LuaNative script_database{};
    // 只在持久胜利已锁定后调用；true表示落点拾取，false表示三回合用尽。
    std::function<std::vector<Bytes>(bool)> finish_boss_chest{};
    // 4010先刷新所有角色的条件装备属性，再处理回血、光环及连续攻击。
    std::function<void()> refresh_equipment{};
};
// 双角色移动，支持显式配置的移动卡状态；动态物件与其他控制状态另行接入。
// 每个落点都必须显式处理；未知事件不得直接推进回合。
// 这里提供引擎接入点，尚非完整的 BOSS 玩法实现。
RichonlineStartupPlan make_richonline_boss_turns(const RichonlineBossStartup& startup,
    RichonlineRoadTopology topology, RichonlineBossTurnRules rules);
}
