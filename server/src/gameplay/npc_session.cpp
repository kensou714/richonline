#include "richonline_npc_session.hpp"
#include <algorithm>
#include <iterator>
#include <limits>
#include <type_traits>

namespace richnet {
static_assert(std::is_nothrow_move_assignable_v<RichonlineNpcSpawner>);
static_assert(std::is_nothrow_copy_assignable_v<RichonlineActorStatus>);
static_assert(std::is_nothrow_copy_assignable_v<RichonlinePossessionClock>);
namespace {
void append(std::vector<Bytes>& to,std::vector<Bytes> from) {
    to.insert(to.end(),std::make_move_iterator(from.begin()),std::make_move_iterator(from.end()));
}
Bytes stop(std::uint16_t game,std::int16_t position) {
    Bytes bytes;append_le(bytes,0x4013,2);append_le(bytes,game,2);
    append_le(bytes,static_cast<std::uint16_t>(position),2);return bytes;
}
bool same_clock(const RichonlinePossessionClock& left,const RichonlinePossessionClock& right) noexcept {
    return left.npc==right.npc && left.turns==right.turns && left.last_actor_turn==right.last_actor_turn;
}
}
RichonlineNpcSession::RichonlineNpcSession(std::uint16_t game,std::string map,
    RichonlineNpcRules rules,std::shared_ptr<const RichonlineChanceResources> resources,
    std::shared_ptr<const RichonlineChanceEventTable> events,std::shared_ptr<RichonlineGameLedger> ledger,
    std::shared_ptr<RichonlineBossCards> cards,std::shared_ptr<RichonlineGroundObjects> ground,
    RichonlineNpcSessionPolicy policy)
    :game_(game),map_(std::move(map)),rules_(std::move(rules)),resources_(std::move(resources)),
    events_(std::move(events)),ledger_(std::move(ledger)),cards_(std::move(cards)),ground_(std::move(ground)),
    policy_(std::move(policy)),spawner_(game_,policy_.spawn,policy_.spawn_seed) {
    if(!resources_ || !events_ || !ledger_ || !cards_ || !ground_ || ledger_->actor_count()!=2 ||
        map_.empty() || cards_->map_name()!=map_ || policy_.money_policy_name.empty() || !policy_.money_amount ||
        policy_.actor44[0]==policy_.actor44[1] ||
        ((policy_.spawn.initial_chests || policy_.spawn.refresh_chests) && !policy_.ticket_chest) ||
        !std::all_of(policy_.spawn.god_pool.begin(),policy_.spawn.god_pool.end(),[this](auto npc){return supported_npc(npc);}))
        throw CodecError("richonline_npc_session_policy_unclosed");
    for(const auto duration:policy_.money_affix_turns)
        if(!duration || duration>127) throw CodecError("richonline_npc_session_affix_invalid");
    if(!rules_.fortune_affix_turns || rules_.fortune_affix_turns>127)
        throw CodecError("richonline_npc_session_affix_invalid");
    if(policy_.badluck && (!policy_.badluck->resource_affix_turns || policy_.badluck->resource_affix_turns>127 ||
        policy_.badluck->selection_policy_name.empty() || !policy_.badluck->lost_slots))
        throw CodecError("richonline_npc_session_badluck_policy_invalid");
    if(policy_.ticket_chest && !policy_.ticket_chest->tickets)
        throw CodecError("richonline_npc_session_chest_policy_invalid");
    if(policy_.sleep_deity && (!policy_.sleep_deity->resource_affix_turns || policy_.sleep_deity->resource_affix_turns>127 ||
        policy_.sleep_deity->protection_policy_name.empty() || !policy_.sleep_deity->protection))
        throw CodecError("richonline_npc_session_sleep_policy_invalid");
    for(const auto card:policy_.fortune_cards)
        if(!resources_->contains_card(card)) throw CodecError("richonline_npc_session_reward_invalid");
    if(policy_.temple_aura_affix) for(const auto turns:*policy_.temple_aura_affix)
        if(!turns || turns>127) throw CodecError("richonline_npc_session_affix_invalid");
    // Validate the exact map before any initialization mutates shared ground.
    static_cast<void>(events_->size(map_));
}
bool RichonlineNpcSession::supported_npc(std::int8_t npc) const noexcept {
    return npc==0 || npc==1 || npc==3 || (npc==2 && policy_.badluck.has_value()) ||
        ((npc==4 || npc==6) && policy_.temple_aura_affix.has_value()) ||
        (npc==7 && policy_.sleep_deity.has_value());
}
std::uint8_t RichonlineNpcSession::affix_turns(std::int8_t npc) const {
    if(npc==0 || npc==1) return policy_.money_affix_turns[static_cast<std::size_t>(npc)];
    if(npc==2 && policy_.badluck) return policy_.badluck->resource_affix_turns;
    if(npc==3) return rules_.fortune_affix_turns;
    if((npc==4 || npc==6) && policy_.temple_aura_affix)
        return (*policy_.temple_aura_affix)[npc==4 ? 0 : 1];
    if(npc==7 && policy_.sleep_deity) return policy_.sleep_deity->resource_affix_turns;
    throw CodecError("richonline_npc_session_affix_unsupported");
}
void RichonlineNpcSession::check_actor(std::uint8_t actor,const RichonlineActorStatus& status) const {
    if(!initialized_ || actor>=clocks_.size()) throw CodecError("richonline_npc_session_actor_invalid");
    const auto& clock=clocks_[actor];
    if(clock.npc!=status.possession || (clock.npc && !supported_npc(*clock.npc)) ||
        (!clock.npc && clock.turns)) throw CodecError("richonline_npc_session_status_desynchronized");
}
void RichonlineNpcSession::admit_clock_change(std::uint8_t actor) const {
    if(clock_generations_[actor]==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_npc_session_clock_generation_exhausted");
}
RichonlineNpcSession::PreparedStatusChange RichonlineNpcSession::prepare_status_change(std::uint8_t actor,
    const RichonlineActorStatus& before,const RichonlineActorStatus& after) const {
    check_actor(actor,before);admit_clock_change(actor);
    if(after.possession && after.possession!=before.possession)
        throw CodecError("richonline_npc_session_external_attachment_forbidden");
    if(after.possession_multiplier1744!=before.possession_multiplier1744 ||
        (after.possession_strength1740!=before.possession_strength1740 &&
            !(!after.possession && before.possession_strength1740>0 && after.possession_strength1740==0)))
        throw CodecError("richonline_npc_session_external_strength_forbidden");
    if(before.possession!=after.possession && pending_ && pending_->actor==actor)
        throw CodecError("richonline_npc_session_detach_pending");
    PreparedStatusChange result;result.owner_=this;result.actor_=actor;result.generation_=clock_generations_[actor];
    result.before_status_=before;result.after_status_=after;
    result.before_clock_=clocks_[actor];result.after_clock_=result.before_clock_;
    if(!after.possession) {
        richonline_detach_possession(result.after_status_);
        result.after_clock_.npc.reset();result.after_clock_.turns=0;
    }
    return result;
}
RichonlineNpcSession::PreparedStatusChange RichonlineNpcSession::prepare_card_detachment(
    const RichonlineLandingContext& source,std::uint8_t target,const RichonlineActorStatus& before) const {
    check_actor(source.actor_slot,source.actor_status);
    if(pending_ || source.game_mode!=3 || source.synthetic_actor)
        throw CodecError("richonline_npc_session_card_out_of_phase");
    if(target==source.actor_slot && before!=source.actor_status)
        throw CodecError("richonline_npc_session_context_stale");
    if(!before.possession) throw CodecError("richonline_deity_card_no_possession");
    auto after=before;richonline_detach_possession(after);
    auto plan=prepare_status_change(target,before,after);
    plan.requires_idle_=true;return plan;
}
RichonlineNpcSession::PreparedStatusChange RichonlineNpcSession::prepare_card_attachment(
    const RichonlineLandingContext& source,std::int8_t npc,std::uint16_t calendar,
    const RichonlineActorStatus& before) const {
    const auto actor=source.actor_slot;
    check_actor(actor,before);admit_clock_change(actor);
    if(pending_ || source.game_mode!=3 || source.synthetic_actor || source.actor_status!=before || (npc!=0 && npc!=3))
        throw CodecError("richonline_npc_session_card_out_of_phase");
    auto after=before;
    if(after.possession) richonline_detach_possession(after);
    after.possession=npc;
    PreparedStatusChange plan;plan.owner_=this;plan.actor_=actor;plan.generation_=clock_generations_[actor];
    plan.before_status_=before;plan.after_status_=after;
    plan.before_clock_=clocks_[actor];plan.after_clock_=plan.before_clock_;
    plan.after_clock_.npc=npc;plan.after_clock_.turns=affix_turns(npc);plan.requires_idle_=true;
    if(npc==0) plan.card_roulette_calendar_=calendar;
    return plan;
}
RichonlineFortuneRewardPlan RichonlineNpcSession::prepare_fortune_rewards(
    const RichonlineChanceInventory& inventory) const {
    if(!initialized_ || pending_) throw CodecError("richonline_npc_session_card_out_of_phase");
    const auto chosen=policy_.fortune_selection ? policy_.fortune_selection(inventory) : policy_.fortune_cards;
    return prepare_richonline_fortune_rewards(game_,*resources_,*events_,map_,chosen,inventory);
}
RichonlineNpcSession::PreparedStatusChange RichonlineNpcSession::prepare_temple_change(std::uint8_t actor,
    const RichonlineTemplePossessionChange& change) const {
    check_actor(actor,change.expected);
    if(pending_) throw CodecError("richonline_npc_temple_out_of_phase");
    if(change.summon) {
        if(change.strength) throw CodecError("richonline_npc_temple_strength_invalid");
        if(change.expected.possession || !policy_.temple_aura_affix ||
            (*change.summon!=4 && *change.summon!=6))
            throw CodecError("richonline_npc_temple_summon_unsupported");
        admit_clock_change(actor);
        PreparedStatusChange plan;plan.owner_=this;plan.actor_=actor;plan.generation_=clock_generations_[actor];
        plan.before_status_=change.expected;plan.after_status_=change.expected;
        plan.after_status_.possession=change.summon;
        plan.before_clock_=clocks_[actor];plan.after_clock_=plan.before_clock_;
        plan.after_clock_.npc=change.summon;
        plan.after_clock_.turns=(*policy_.temple_aura_affix)[*change.summon==4?0:1];
        plan.requires_idle_=true;return plan;
    }
    if(!change.expected.possession) throw CodecError("richonline_npc_temple_out_of_phase");
    if(!change.extend && change.strength) throw CodecError("richonline_npc_temple_strength_invalid");
    const auto duration=plan_richonline_temple_duration(clocks_[actor].turns,change.extend,change.days,change.maximum);
    auto after=change.expected;
    if(!duration) richonline_detach_possession(after);
    auto plan=prepare_status_change(actor,change.expected,after);
    if(duration && change.extend && change.strength>0) richonline_set_possession_strength(plan.after_status_,change.strength);
    plan.after_clock_.turns=duration.value_or(0);
    plan.requires_idle_=true;
    return plan;
}
bool RichonlineNpcSession::matches_status_change(const PreparedStatusChange& plan,
    const RichonlineActorStatus& authoritative) const noexcept {
    return plan.owner_==this && initialized_ && !plan.committed_ && plan.actor_<clocks_.size() &&
        clock_generations_[plan.actor_]==plan.generation_ && authoritative==plan.before_status_ &&
        same_clock(clocks_[plan.actor_],plan.before_clock_) &&
        !(plan.requires_idle_ && pending_) &&
        !(plan.before_status_.possession!=plan.after_status_.possession && pending_ && pending_->actor==plan.actor_);
}
RichonlineNpcSessionResult RichonlineNpcSession::temple_summon(const RichonlineLandingContext& context,
    std::uint16_t calendar,std::int8_t npc,RichonlineActorStatus& status) {
    check_actor(context.actor_slot,status);
    if(pending_ || context.game_mode!=3 || context.position<0 || context.actor_status!=status ||
        status.possession || context.synthetic_actor!=(context.actor_slot==1) || npc<0 || npc>3 || !supported_npc(npc))
        throw CodecError("richonline_npc_temple_summon_unsupported");
    admit_clock_change(context.actor_slot);
    auto next_status=status;next_status.possession=npc;
    auto next_clock=clocks_[context.actor_slot];next_clock.npc=npc;next_clock.turns=affix_turns(npc);
    auto next_inventory=cards_->inventory();
    RichonlineNpcSessionResult result{{},RichonlineNpcContinuation::landing_phase6,RichonlineNpcWait::none,false,{}};
    std::optional<RichonlineDeityMoneyPlan> money;
    if(npc==3) {
        auto fortune=plan_richonline_fortune({game_,context.actor_slot,context.position,context.synthetic_actor,
            RichonlineNpcOrigin::temple,{}},rules_,*resources_,*events_,map_,
            !context.synthetic_actor && policy_.fortune_selection ? policy_.fortune_selection(next_inventory) : policy_.fortune_cards,
            next_inventory,next_status,ledger_->snapshot(context.actor_slot));
        result.messages=std::move(fortune.messages);next_inventory=fortune.inventory_after;
    } else if(npc==2) {
        const auto slots=context.synthetic_actor ? std::array<std::int8_t,4>{-1,-1,-1,-1} :
            policy_.badluck->lost_slots(next_inventory);
        auto badluck=plan_richonline_badluck(game_,RichonlineDeityMoneyOrigin::temple,context.synthetic_actor,
            slots,*resources_,next_inventory,next_status,*events_);
        result.messages=std::move(badluck.messages);next_inventory=badluck.inventory_after;
    } else if(context.synthetic_actor) {
        const std::array before{ledger_->snapshot(0),ledger_->snapshot(1)};
        money=plan_richonline_deity_money({game_,context.actor_slot,RichonlineDeityMoneyOrigin::temple,policy_.actor44},
            policy_.money_amount(context.actor_slot,npc,before),next_status,before);
        result.messages.push_back(money->response4022);
        result.wait=money->awaits_settlement ? RichonlineNpcWait::settlement : RichonlineNpcWait::none;
        result.bankrupt_actor=money->bankrupt_actor;
    } else result.wait=RichonlineNpcWait::roulette34;
    if(money && !commit_richonline_deity_money(*ledger_,*money,[]{return true;}))
        throw CodecError("richonline_npc_session_ledger_rejected");
    cards_->commit_inventory(next_inventory);status=next_status;
    clocks_[context.actor_slot]=next_clock;++clock_generations_[context.actor_slot];
    if(result.wait!=RichonlineNpcWait::none)
        pending_=PendingMoney{context.actor_slot,calendar,npc,RichonlineDeityMoneyOrigin::temple,
            result.wait==RichonlineNpcWait::settlement};
    return result;
}
bool RichonlineNpcSession::commit_status_change(PreparedStatusChange& plan,RichonlineActorStatus& authoritative) noexcept {
    if(!matches_status_change(plan,authoritative)) return false;
    authoritative=plan.after_status_;clocks_[plan.actor_]=plan.after_clock_;
    if(plan.card_roulette_calendar_)
        pending_=PendingMoney{plan.actor_,*plan.card_roulette_calendar_,0,RichonlineDeityMoneyOrigin::summoned_card,false};
    ++clock_generations_[plan.actor_];plan.committed_=true;return true;
}
void RichonlineNpcSession::detach(std::uint8_t actor,RichonlineActorStatus& status) {
    auto after=status;richonline_detach_possession(after);auto plan=prepare_status_change(actor,status,after);
    if(!commit_status_change(plan,status)) throw CodecError("richonline_npc_session_status_change_stale");
}
RichonlineNpcSpawnResult RichonlineNpcSession::initial(std::span<const std::int16_t> reserved) {
    if(initialized_) throw CodecError("richonline_npc_session_duplicate_initial");
    auto result=spawner_.initialize(*ground_,reserved); initialized_=true; return result;
}
void RichonlineNpcSession::configure_placement_reservations(std::function<std::vector<std::int16_t>()> source) {
    placement_reservations_=std::move(source);
}
std::vector<std::int16_t> RichonlineNpcSession::placement_reservations() const {
    return placement_reservations_ ? placement_reservations_() : std::vector<std::int16_t>{};
}
RichonlineNpcSpawnResult RichonlineNpcSession::finish_round(std::uint64_t round) {
    if(!initialized_ || pending_) throw CodecError("richonline_npc_session_round_out_of_phase");
    const auto reserved=placement_reservations();
    return spawner_.finish_round(*ground_,round,reserved);
}
RichonlinePossessionTick RichonlineNpcSession::actor_begin(std::uint8_t actor,std::uint64_t turn,
    RichonlineActorStatus& status) {
    check_actor(actor,status);
    if(pending_) throw CodecError("richonline_npc_session_actor_begin_pending");
    auto tick=tick_richonline_possession(clocks_[actor],status,turn);
    if(!tick.duplicate) admit_clock_change(actor);
    clocks_[actor]=tick.clock;status=tick.status;
    if(!tick.duplicate) ++clock_generations_[actor];
    return tick;
}
std::optional<RichonlineNpcSessionResult> RichonlineNpcSession::landing(const RichonlineLandingContext& context,
    std::uint16_t calendar,RichonlineActorStatus& status,
    const std::function<void(const RichonlineLandingContext&)>& preflight) {
    check_actor(context.actor_slot,status);
    if(pending_) throw CodecError("richonline_npc_session_landing_pending");
    if(context.actor_status!=status) throw CodecError("richonline_npc_session_context_stale");
    if(context.game_mode!=3) return {};
    const auto before_ground=ground_->snapshot();
    const auto found=before_ground.objects.find(context.position);
    if(found==before_ground.objects.end()) return {};
    if(found->second.npc==9 && policy_.ticket_chest) return chest_landing(context,before_ground,found->second);
    if(!supported_npc(found->second.npc)) return {};
    admit_clock_change(context.actor_slot);
    const auto npc=found->second.npc;
    auto next_clock=clocks_[context.actor_slot];next_clock.npc=npc;
    next_clock.turns=affix_turns(npc);
    auto staged_ground=*ground_;auto staged_spawner=spawner_;
    if(!staged_ground.consume(context.position,found->second)) throw CodecError("richonline_npc_session_ground_stale");
    auto next_status=status;
    // NEW7C3220 queues6050 before6051 when replacing an attached god.
    if(next_status.possession) richonline_detach_possession(next_status);
    next_status.possession=npc;
    auto next_inventory=cards_->inventory();
    std::optional<RichonlineDeityMoneyPlan> immediate_money;
    RichonlineNpcSessionResult result{{},RichonlineNpcContinuation::landing_phase1,RichonlineNpcWait::none,true,{}};
    if(npc==3) {
        const auto plan=plan_richonline_fortune({game_,context.actor_slot,context.position,context.synthetic_actor,
            RichonlineNpcOrigin::ground,{}},rules_,*resources_,*events_,map_,
            !context.synthetic_actor && policy_.fortune_selection ? policy_.fortune_selection(next_inventory) : policy_.fortune_cards,
            cards_->inventory(),next_status,ledger_->snapshot(context.actor_slot));
        result.messages=plan.messages;next_inventory=plan.inventory_after;next_status=plan.status_after;
    } else if(npc==2) {
        const auto slots=context.synthetic_actor ? std::array<std::int8_t,4>{-1,-1,-1,-1} :
            policy_.badluck->lost_slots(next_inventory);
        const auto plan=plan_richonline_badluck(game_,RichonlineDeityMoneyOrigin::ground,context.synthetic_actor,
            slots,*resources_,next_inventory,next_status,*events_);
        result.messages.push_back(stop(game_,context.position));append(result.messages,plan.messages);
        next_inventory=plan.inventory_after;
    } else if(npc==4 || npc==6) {
        // NEW7C3220 returns1 after6051: continue the landing without roulette.
        result.messages.push_back(stop(game_,context.position));
    } else if(npc==7) {
        const auto own_inventory=context.synthetic_actor ? RichonlineChanceInventory{} : next_inventory;
        const auto protection=policy_.sleep_deity->protection(context.actor_slot,own_inventory,next_status);
        const auto plan=plan_richonline_sleep_deity(policy_.sleep_deity->resource_affix_turns,
            *resources_,own_inventory,next_status,protection);
        result.messages.push_back(stop(game_,context.position));
        if(!context.synthetic_actor) next_inventory=plan.inventory_after;
        next_status=plan.status_after;next_clock.npc=next_status.possession;next_clock.turns=plan.possession_turns;
    } else {
        result.messages.push_back(stop(game_,context.position));
        if(context.synthetic_actor) {
            const std::array before{ledger_->snapshot(0),ledger_->snapshot(1)};
            const auto amount=policy_.money_amount(context.actor_slot,npc,before);
            immediate_money=plan_richonline_deity_money({game_,context.actor_slot,
                RichonlineDeityMoneyOrigin::ground,policy_.actor44},amount,next_status,before);
            result.messages.push_back(immediate_money->response4022);
            result.wait=immediate_money->awaits_settlement ? RichonlineNpcWait::settlement : RichonlineNpcWait::none;
            result.bankrupt_actor=immediate_money->bankrupt_actor;
        } else result.wait=RichonlineNpcWait::roulette34;
    }
    // Ground attachment precedes the property phase. Validate that phase using
    // the projected possession before committing rewards, money or ground.
    if(preflight && result.wait!=RichonlineNpcWait::settlement) {
        auto continuation=context;continuation.actor_status=next_status;
        preflight(continuation);
    }
    const auto reserved=placement_reservations();
    append(result.messages,staged_spawner.replenish_minimum(staged_ground,reserved).messages);
    // All fallible planning/allocation precedes shared commits. No owner callback
    // runs in this span; the room executor serializes ground/cards/status access.
    auto prepared_ground=ground_->prepare(before_ground,staged_ground.snapshot().objects);
    const auto commit_ground=[&] {
        if(!ground_->commit_prepared(prepared_ground)) throw CodecError("richonline_npc_session_ground_stale");
        return true;
    };
    if(immediate_money) {
        if(!commit_richonline_deity_money(*ledger_,*immediate_money,commit_ground))
            throw CodecError("richonline_npc_session_ledger_rejected");
    } else commit_ground();
    spawner_=std::move(staged_spawner);cards_->commit_inventory(next_inventory);
    status=next_status;clocks_[context.actor_slot]=next_clock;++clock_generations_[context.actor_slot];
    if(npc!=3 && result.wait!=RichonlineNpcWait::none)
        pending_=PendingMoney{context.actor_slot,calendar,npc,RichonlineDeityMoneyOrigin::ground,
            result.wait==RichonlineNpcWait::settlement};
    return result;
}
std::optional<RichonlineNpcSessionResult> RichonlineNpcSession::chest_landing(const RichonlineLandingContext& context,
    const RichonlineGroundSnapshot& before_ground,const RichonlineGroundObject& object) {
    const auto plan=plan_richonline_ticket_chest(*policy_.ticket_chest,context.synthetic_actor,
        context.actor_status,ledger_->snapshot(context.actor_slot));
    if(!plan.remove_ground_npc) return {};
    auto staged_ground=*ground_;auto staged_spawner=spawner_;
    if(!staged_ground.consume(context.position,object)) throw CodecError("richonline_npc_session_ground_stale");
    RichonlineNpcSessionResult result{{stop(game_,context.position)},plan.continuation,RichonlineNpcWait::none,true,{}};
    const auto reserved=placement_reservations();
    append(result.messages,staged_spawner.replenish_minimum(staged_ground,reserved).messages);
    auto prepared_ground=ground_->prepare(before_ground,staged_ground.snapshot().objects);
    const auto commit_ground=[&] {
        if(!ground_->commit_prepared(prepared_ground)) throw CodecError("richonline_npc_session_ground_stale");
        return true;
    };
    if(plan.after!=plan.before.funds) {
        const std::array updates{RichonlineGameFundsUpdate{context.actor_slot,plan.before,plan.after}};
        if(!ledger_->commit_batch(updates,commit_ground)) throw CodecError("richonline_npc_session_ledger_rejected");
    } else commit_ground();
    spawner_=std::move(staged_spawner);return result;
}
RichonlineNpcSessionResult RichonlineNpcSession::handle(View request,std::uint8_t actor,RichonlineActorStatus& status) {
    const auto decoded=decode_richonline_deity_roulette(request);
    check_actor(actor,status);
    if(!pending_ || pending_->settlement || pending_->actor!=actor || pending_->calendar!=decoded.calendar ||
        status.possession!=pending_->npc) throw CodecError("richonline_npc_session_roulette_out_of_phase");
    return resolve_roulette(actor,status);
}
RichonlineNpcSessionResult RichonlineNpcSession::resolve_roulette(std::uint8_t actor,RichonlineActorStatus& status) {
    check_actor(actor,status);
    if(!pending_ || pending_->settlement || pending_->actor!=actor || status.possession!=pending_->npc)
        throw CodecError("richonline_npc_session_roulette_out_of_phase");
    const std::array before{ledger_->snapshot(0),ledger_->snapshot(1)};
    const auto amount=policy_.money_amount(actor,pending_->npc,before);
    const auto planned=plan_richonline_deity_money({game_,actor,pending_->origin,policy_.actor44},amount,status,before);
    RichonlineNpcSessionResult result{{planned.response4022},planned.continuation,
        planned.awaits_settlement ? RichonlineNpcWait::settlement : RichonlineNpcWait::none,false,planned.bankrupt_actor};
    if(!commit_richonline_deity_money(*ledger_,planned,[]{return true;}))
        throw CodecError("richonline_npc_session_ledger_rejected");
    if(planned.awaits_settlement) pending_->settlement=true;else pending_.reset();
    return result;
}
RichonlineNpcSessionResult RichonlineNpcSession::fortune_card(View request,const RichonlineLandingContext& context,
    RichonlineActorStatus& status) {
    const auto decoded=decode_richonline_fortune_card(request);
    check_actor(context.actor_slot,status);
    if(pending_ || context.game_mode!=3 || context.synthetic_actor || context.actor_status!=status)
        throw CodecError("richonline_npc_session_card_out_of_phase");
    admit_clock_change(context.actor_slot);
    const auto consumption=cards_->prepare_consumption(decoded.slot,1070);
    if(!consumption) throw CodecError("richonline_fortune_card_missing");
    const auto chosen=policy_.fortune_selection ? policy_.fortune_selection(consumption->remaining_inventory) : policy_.fortune_cards;
    const auto plan=plan_richonline_fortune({game_,context.actor_slot,context.position,false,
        RichonlineNpcOrigin::fortune_card1070,decoded},rules_,*resources_,*events_,map_,chosen,
        cards_->inventory(),status,ledger_->snapshot(context.actor_slot));
    RichonlineNpcSessionResult result{plan.messages,plan.continuation,RichonlineNpcWait::none,false,{}};
    auto next_clock=clocks_[context.actor_slot];next_clock.npc=3;next_clock.turns=plan.possession_turns;
    cards_->commit_inventory(plan.inventory_after);status=plan.status_after;clocks_[context.actor_slot]=next_clock;
    ++clock_generations_[context.actor_slot];
    return result;
}
bool RichonlineNpcSession::awaiting_roulette() const noexcept {return pending_ && !pending_->settlement;}
RichonlineNpcSessionResult RichonlineNpcSession::wealth_card(View request,const RichonlineLandingContext& context,
    RichonlineActorStatus& status) {
    const auto decoded=decode_richonline_wealth_card(request);
    check_actor(context.actor_slot,status);
    if(pending_ || context.game_mode!=3 || context.synthetic_actor || context.actor_status!=status)
        throw CodecError("richonline_npc_session_card_out_of_phase");
    admit_clock_change(context.actor_slot);
    const auto plan=plan_richonline_wealth_card(game_,decoded,policy_.money_affix_turns[0],
        *resources_,cards_->inventory(),status);
    RichonlineNpcSessionResult result{{plan.response40d2},RichonlineNpcContinuation::restore_action,
        RichonlineNpcWait::roulette34,false,{}};
    auto next_clock=clocks_[context.actor_slot];next_clock.npc=0;next_clock.turns=plan.possession_turns;
    cards_->commit_inventory(plan.inventory_after);status=plan.status_after;clocks_[context.actor_slot]=next_clock;
    ++clock_generations_[context.actor_slot];
    pending_=PendingMoney{context.actor_slot,decoded.calendar,0,plan.money_origin,false};
    return result;
}
RichonlineNpcSessionResult RichonlineNpcSession::deity_card(View request,const RichonlineLandingContext& source,
    std::uint16_t calendar,RichonlineActorStatus& target_status,bool target_selectable,
    std::span<const std::int16_t> candidates_allowed,const RichonlineRouteChooser& choose) {
    const auto decoded=parse_richonline_deity_card(request);
    check_actor(source.actor_slot,source.actor_status);
    if(pending_ || source.game_mode!=3 || source.synthetic_actor || decoded.target_actor<0 ||
        decoded.target_actor>=static_cast<std::int8_t>(clocks_.size()))
        throw CodecError("richonline_npc_session_card_out_of_phase");
    if(decoded.calendar!=calendar) throw CodecError("richonline_deity_card_calendar_mismatch");
    if(!target_selectable) throw CodecError("richonline_deity_card_target_invalid");
    if(!cards_->prepare_consumption(decoded.slot,decoded.kind==RichonlineDeityCard::summon1047 ? 1047 : 1048))
        throw CodecError("richonline_deity_card_not_owned");
    const auto target=static_cast<std::uint8_t>(decoded.target_actor);
    check_actor(target,target_status);
    admit_clock_change(target);
    if(target==source.actor_slot && target_status!=source.actor_status)
        throw CodecError("richonline_npc_session_context_stale");
    const auto before_ground=ground_->snapshot();
    std::optional<RichonlineSummonedNpc> selected;
    if(decoded.kind==RichonlineDeityCard::summon1047) {
        if(!choose) throw CodecError("richonline_npc_session_summon_policy_missing");
        std::vector<std::pair<std::int16_t,RichonlineGroundObject>> candidates;
        for(const auto position:candidates_allowed) {
            const auto entry=before_ground.objects.find(position);
            if(entry!=before_ground.objects.end() && supported_npc(entry->second.npc))
                candidates.push_back(*entry);
        }
        if(candidates.empty()) throw CodecError("richonline_npc_session_visible_god_missing");
        const auto index=choose(candidates.size());
        if(index>=candidates.size()) throw CodecError("richonline_npc_session_summon_rng_invalid");
        const auto [position,object]=candidates[index];
        const auto duration=affix_turns(object.npc);
        selected=RichonlineSummonedNpc{position,object.npc,duration,true,true};
    }
    const auto plan=plan_richonline_deity_card(game_,decoded,calendar,
        {decoded.target_actor,true,target_selectable,target_status},selected,*cards_,source.actor_slot);
    auto next_inventory=plan.consumption.remaining_inventory;
    auto next_status=plan.after.status;
    auto next_clock=clocks_[target];next_clock.npc=next_status.possession;next_clock.turns=plan.possession_turns;
    RichonlineNpcSessionResult result{{plan.response},RichonlineNpcContinuation::restore_action,RichonlineNpcWait::none,false,{}};
    if(selected && target==source.actor_slot) {
        if(selected->id==3) {
            const auto fortune=plan_richonline_fortune({game_,target,source.position,false,RichonlineNpcOrigin::temple,{}},
                rules_,*resources_,*events_,map_,
                policy_.fortune_selection ? policy_.fortune_selection(next_inventory) : policy_.fortune_cards,
                next_inventory,next_status,ledger_->snapshot(target));
            append(result.messages,fortune.messages);next_inventory=fortune.inventory_after;next_status=fortune.status_after;
        } else if(selected->id==2) {
            const auto badluck=plan_richonline_badluck(game_,RichonlineDeityMoneyOrigin::summoned_card,false,
                policy_.badluck->lost_slots(next_inventory),*resources_,next_inventory,next_status,*events_);
            append(result.messages,badluck.messages);next_inventory=badluck.inventory_after;
        } else if(selected->id==0 || selected->id==1) result.wait=RichonlineNpcWait::roulette34;
    }
    if(selected && selected->id==7) {
        const auto own_inventory=target==source.actor_slot ? next_inventory : RichonlineChanceInventory{};
        const auto protection=policy_.sleep_deity->protection(target,own_inventory,next_status);
        const auto sleep=plan_richonline_sleep_deity(policy_.sleep_deity->resource_affix_turns,
            *resources_,own_inventory,next_status,protection);
        if(target==source.actor_slot) next_inventory=sleep.inventory_after;
        next_status=sleep.status_after;next_clock.npc=next_status.possession;next_clock.turns=sleep.possession_turns;
        result.wait=RichonlineNpcWait::none;
    }
    auto staged_ground=*ground_;auto staged_spawner=spawner_;
    if(selected) {
        if(!staged_ground.consume(selected->position,before_ground.objects.at(selected->position)))
            throw CodecError("richonline_npc_session_ground_stale");
        const auto reserved=placement_reservations();
        append(result.messages,staged_spawner.replenish_minimum(staged_ground,reserved).messages);
    }
    auto prepared_ground=ground_->prepare(before_ground,staged_ground.snapshot().objects);
    if(cards_->inventory()!=plan.consumption.source_inventory)
        throw CodecError("richonline_npc_session_inventory_changed");
    if(!ground_->commit_prepared(prepared_ground)) throw CodecError("richonline_npc_session_ground_stale");
    spawner_=std::move(staged_spawner);cards_->commit_inventory(next_inventory);
    target_status=next_status;clocks_[target]=next_clock;++clock_generations_[target];
    result.summoned=selected;
    if(result.wait==RichonlineNpcWait::roulette34)
        pending_=PendingMoney{source.actor_slot,decoded.calendar,*next_status.possession,RichonlineDeityMoneyOrigin::summoned_card,false};
    return result;
}
bool RichonlineNpcSession::awaiting_settlement() const noexcept {return pending_ && pending_->settlement;}
}
