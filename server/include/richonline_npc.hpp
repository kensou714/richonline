#pragma once
#include "richonline_actor_status.hpp"
#include "richonline_game_ledger.hpp"
#include "richonline_boss_cards.hpp"

namespace richnet {
enum class RichonlineNpcOrigin { ground, temple, fortune_card1070 };
enum class RichonlineNpcContinuation { landing_phase1, landing_phase6, restore_action };
struct RichonlineFortuneCardRequest {
    std::uint16_t calendar;
    std::int8_t slot,bank;
};
RichonlineFortuneCardRequest decode_richonline_fortune_card(View);
std::uint8_t parse_richonline_npc_affix(std::string_view npc,std::int8_t kind);
std::uint8_t load_richonline_npc_affix(const std::filesystem::path& root,std::int8_t kind);
// Values come from NEW Npc.kpd; card selection is an explicit server policy.
struct RichonlineNpcRules {
    std::uint8_t fortune_affix_turns;
    static RichonlineNpcRules parse(std::string_view npc);
    static RichonlineNpcRules load(const std::filesystem::path& root);
};
struct RichonlineFortuneContext {
    std::uint16_t game_id;
    std::uint8_t actor;
    std::int16_t position;
    bool synthetic;
    RichonlineNpcOrigin origin;
    std::optional<RichonlineFortuneCardRequest> card;
};
struct RichonlineFortunePlan {
    std::vector<Bytes> messages;
    RichonlineChanceInventory inventory_before,inventory_after;
    RichonlineActorStatus status_before,status_after;
    RichonlineGameFundsSnapshot funds_before;
    RichonlineGameFunds funds_after;
    std::uint8_t possession_turns;
    RichonlineNpcContinuation continuation;
    bool remove_ground_npc;
    // 4023 adds both cards and continues locally. No C2S acknowledgement exists.
    bool expects_ack=false;
};
// Caller serializes state, checks before snapshots, commits once, then sends.
// Ground includes 4013; temple is invoked after its existing 4013/building phase.
RichonlineFortunePlan plan_richonline_fortune(const RichonlineFortuneContext&,
    const RichonlineNpcRules&,const RichonlineChanceResources&,const RichonlineChanceEventTable&,
    std::string_view map,std::array<std::int16_t,2> policy_cards,
    const RichonlineChanceInventory&,const RichonlineActorStatus&,const RichonlineGameFundsSnapshot&);

struct RichonlineDeityRouletteRequest { std::uint16_t calendar; std::uint8_t unread5; };
RichonlineDeityRouletteRequest decode_richonline_deity_roulette(View);
enum class RichonlineDeityMoneyOrigin { ground, temple, summoned_card };
struct RichonlineDeityMoneyContext {
    std::uint16_t game_id;
    std::uint8_t actor;
    RichonlineDeityMoneyOrigin origin;
    // Caller supplies actual actor+44 values. NEW compares them for NPC0;
    // their wider identity semantics are intentionally not guessed here.
    std::array<std::int32_t,2> actor44;
};
struct RichonlineDeityMoneyPlan {
    Bytes response4022;
    std::array<RichonlineGameFundsSnapshot,2> before;
    std::array<RichonlineGameFunds,2> after;
    std::optional<std::uint8_t> bankrupt_actor;
    RichonlineNpcContinuation continuation;
    bool awaits_settlement;
    bool expects_ack=false;
};
// Completes an already attached NPC0/1 roulette in mode3 with two active actors.
// Caller chooses a nonnegative signed16 result under explicit server policy;
// no original probability table is claimed. Zero is a real no-transfer result.
RichonlineDeityMoneyPlan plan_richonline_deity_money(const RichonlineDeityMoneyContext&,
    std::int16_t policy_amount,const RichonlineActorStatus& current,
    const std::array<RichonlineGameFundsSnapshot,2>& before);
bool commit_richonline_deity_money(RichonlineGameLedger&,const RichonlineDeityMoneyPlan&,
    const std::function<bool()>& authorize);
struct RichonlineWealthCardRequest { std::uint16_t calendar; std::int8_t slot,bank; };
RichonlineWealthCardRequest decode_richonline_wealth_card(View);
struct RichonlineWealthCardPlan {
    Bytes response40d2;
    RichonlineChanceInventory inventory_before,inventory_after;
    RichonlineActorStatus status_before,status_after;
    std::uint8_t possession_turns;
    // 40D2 attaches NPC0 then opens the same roulette as a ground deity.
    std::uint16_t expected_request=34;
    RichonlineDeityMoneyOrigin money_origin=RichonlineDeityMoneyOrigin::summoned_card;
};
// Caller validates turn/calendar, commits inventory/status once, then awaits34.
// Duration must be loaded from NEW NPC0 affix using the resource API above.
RichonlineWealthCardPlan plan_richonline_wealth_card(std::uint16_t game,const RichonlineWealthCardRequest&,
    std::uint8_t resource_affix,const RichonlineChanceResources&,
    const RichonlineChanceInventory&,const RichonlineActorStatus&);
struct RichonlineBadluckPlan {
    std::vector<Bytes> messages;
    RichonlineChanceInventory inventory_before,inventory_after;
    RichonlineNpcContinuation continuation;
    bool expects_ack=false;
};
// Explicit server policy: lose floor(total card units / 2), capped by4024's
// four entries and the map limit. Sampling is weighted without replacement.
std::array<std::int8_t,4> select_richonline_badluck_half(RichonlineChanceInventory,
    std::uint8_t limit,const std::function<std::size_t(std::size_t)>& choose);
// Completes an already attached NPC2. 4024 carries four main-inventory slot
// indices, each consuming one card; unused entries are the protocol sentinel -1.
RichonlineBadluckPlan plan_richonline_badluck(std::uint16_t game,RichonlineDeityMoneyOrigin,
    bool synthetic,std::array<std::int8_t,4> policy_slots,const RichonlineChanceResources&,
    const RichonlineChanceInventory&,const RichonlineActorStatus&,const RichonlineChanceEventTable& names);
struct RichonlineTicketChestRules {
    std::uint16_t tickets;
    static RichonlineTicketChestRules parse(std::string_view gvalue);
    static RichonlineTicketChestRules load(const std::filesystem::path& root);
};
struct RichonlineTicketChestPlan {
    RichonlineGameFundsSnapshot before;
    RichonlineGameFunds after;
    bool remove_ground_npc;
    RichonlineNpcContinuation continuation=RichonlineNpcContinuation::landing_phase1;
    bool expects_ack=false;
};
// Called for NPC9 during ground phase0 of an existing 4013 landing. NEW itself
// credits GValue[14] via local6062; sending another funds packet double-credits.
RichonlineTicketChestPlan plan_richonline_ticket_chest(const RichonlineTicketChestRules&,
    bool synthetic,const RichonlineActorStatus&,const RichonlineGameFundsSnapshot&);
struct RichonlineSleepDeityPlan {
    RichonlineChanceInventory inventory_before,inventory_after;
    RichonlineActorStatus status_before,status_after;
    std::uint8_t possession_turns;
    bool blocked_by_protection;
    std::optional<std::uint8_t> consumed_inventory_slot;
};
// Applies the local protection checks after NPC7 is attached. Automatic1071
// activation/map eligibility is supplied by shared card rules, not inferred
// merely from a card id. 4013/40C0 itself performs the matching client removal.
RichonlineSleepDeityPlan plan_richonline_sleep_deity(std::uint8_t resource_affix,
    const RichonlineChanceResources&,const RichonlineChanceInventory&,
    const RichonlineActorStatus&,RichonlineSleepProtection);
}
