#include "richonline_combat_bridge.hpp"
#include "richonline_controlled_dice.hpp"
#include <algorithm>
#include <type_traits>

namespace richnet {
namespace {
bool unchanged(const RichonlineCombatActorRef& ref,const RichonlineCombatActorView& expected) noexcept {
    return ref.status && *ref.status==expected.status && ref.position==expected.position &&
        ref.capabilities.active==expected.active && ref.capabilities.in_hospital==expected.in_hospital &&
        ref.capabilities.in_prison==expected.in_prison && ref.capabilities.mine_immune_vehicle==expected.mine_immune_vehicle &&
        ref.capabilities.attack_modifiers_enabled==expected.attack_modifiers_enabled &&
        ref.placement_present==expected.placement_present && ref.pet_position==expected.pet_position &&
        (!ref.active || *ref.active==expected.active);
}
}
RichonlineCombatBridge::RichonlineCombatBridge(std::uint16_t game,std::shared_ptr<RichonlineGameLedger> ledger,
    std::shared_ptr<RichonlineBossCards> cards,std::shared_ptr<RichonlineGroundObjects> ground,
    std::shared_ptr<RichonlineBossProperty> property,RichonlineCombatWorld world,RichonlineBossCombatPolicy policy)
    :game_(game),ledger_(std::move(ledger)),cards_(std::move(cards)),ground_(std::move(ground)),
     property_(std::move(property)),world_(std::move(world)),policy_(std::move(policy)) {
    if(!ledger_ || ledger_->actor_count()!=2 || !cards_ || !ground_ || !property_ || !world_.resolve_terms ||
        !world_.targets || !world_.building || policy_.projectiles.empty())
        throw CodecError("richonline_combat_bridge_dependencies_invalid");
}
RichonlineCombatBridge::Snapshot RichonlineCombatBridge::snapshot(std::span<const RichonlineCombatActorRef> refs) const {
    if(refs.size()!=2) throw CodecError("richonline_combat_bridge_actors_invalid");
    Snapshot result;
    auto& state=result.combat; state.game_id=game_;state.revision=revision_;
    for(const auto& ref:refs) {
        if(ref.slot>=2 || !ref.status || state.actors[ref.slot] ||
            (ref.active && *ref.active!=ref.capabilities.active))
            throw CodecError("richonline_combat_bridge_actor_invalid");
        RichonlineCombatActorView actor;
        actor.slot=ref.slot;actor.position=ref.position;actor.status=*ref.status;
        actor.active=ref.capabilities.active;actor.in_hospital=ref.capabilities.in_hospital;
        actor.in_prison=ref.capabilities.in_prison;actor.mine_immune_vehicle=ref.capabilities.mine_immune_vehicle;
        actor.attack_modifiers_enabled=ref.capabilities.attack_modifiers_enabled;
        actor.placement_present=ref.placement_present;actor.pet_position=ref.pet_position;
        actor.funds=ledger_->snapshot(ref.slot);
        if(ref.slot==0) actor.inventory=cards_->inventory();
        state.actors[ref.slot]=actor;
    }
    result.property=property_->combat_snapshot();state.buildings=result.property.buildings;
    set_richonline_combat_building_buffs(state,result.property.buffs);
    if(result.property.decision_pending) throw CodecError("richonline_combat_bridge_property_pending");
    result.ground=ground_->snapshot();state.mines.revision=result.ground.revision;state.mines.last_day=last_day_;
    for(const auto& [position,object]:result.ground.objects) {
        if(object.npc==12 || object.npc==27) {
            const auto owner=object.byte7==255?std::int8_t{-1}:static_cast<std::int8_t>(object.byte7);
            if(object.byte7!=255 && object.byte7>=2) throw CodecError("richonline_combat_bridge_mine_owner_invalid");
            state.mines.mines.push_back({position,owner,object.byte8,
                object.npc==27?RichonlineMineKind::super:RichonlineMineKind::normal});
        } else state.dynamic_npcs.push_back({position,static_cast<std::uint8_t>(object.npc)});
    }
    return result;
}
RichonlineCombatBridgeResult RichonlineCombatBridge::apply(std::span<const RichonlineCombatActorRef> refs,
    const Snapshot& before,RichonlineCombatTurnPlan plan,const RichonlineBossProperty::PreparedMissileRound* missile_round,
    const std::function<void(const std::string&)>& log) {
    std::vector<std::string> impact_logs;
    if(log) for(const auto& impact:plan.building_impacts) {
        impact_logs.push_back("richonline_combat_property_impact revision="+std::to_string(before.combat.revision)+
            " actor="+std::to_string(impact.actor)+" effect="+std::to_string(static_cast<unsigned>(impact.effect))+
            " target="+std::to_string(impact.target)+" property="+std::to_string(impact.before.property)+
            " land_protected="+std::to_string(impact.before.ownership_protected)+
            " owner_before="+std::to_string(impact.before.owner.value_or(255))+
            " owner_after="+std::to_string(impact.after.owner.value_or(255))+
            " kind_before="+std::to_string(impact.before.kind)+" kind_after="+std::to_string(impact.after.kind)+
            " level_before="+std::to_string(impact.before.level)+" level_after="+std::to_string(impact.after.level));
    }
    RichonlineGroundMap after_ground;
    for(const auto& npc:plan.after.dynamic_npcs) {
        const auto found=before.ground.objects.find(npc.position);
        if(found==before.ground.objects.end() || found->second.npc!=static_cast<std::int8_t>(npc.type))
            throw CodecError("richonline_combat_bridge_dynamic_transition_invalid");
        after_ground.emplace(npc.position,found->second);
    }
    for(const auto& mine:plan.after.mines.mines)
        if(!after_ground.emplace(mine.position,RichonlineGroundObject{static_cast<std::int8_t>(mine.kind),
            static_cast<std::uint8_t>(mine.owner),mine.remaining_days}).second)
            throw CodecError("richonline_combat_bridge_ground_collision");
    auto prepared_ground=ground_->prepare(before.ground,after_ground);
    const auto buffs=richonline_combat_building_buffs(plan.after);
    const auto prepared_property=property_->prepare_combat(before.property,plan.after.buildings,missile_round,&buffs);
    // Unchanged actors are also checked by the ledger, so a callback cannot
    // change another actor's funds during planning and escape the CAS.
    std::vector<RichonlineGameFundsUpdate> updates;
    for(const auto& ref:refs) updates.push_back({ref.slot,before.combat.actors[ref.slot]->funds,
        plan.after.actors[ref.slot]->funds.funds});
    const auto expected_inventory=before.combat.actors[0]->inventory;
    const auto after_inventory=plan.after.actors[0]->inventory;
    const auto ready=[&]() noexcept {
        if(revision_!=before.combat.revision || last_day_!=before.combat.mines.last_day ||
            cards_->inventory()!=expected_inventory || !ground_->matches(prepared_ground) ||
            !property_->combat_matches(prepared_property)) return false;
        return std::all_of(refs.begin(),refs.end(),[&](const auto& ref) {
            return unchanged(ref,*before.combat.actors[ref.slot]);
        });
    };
    if(!ready()) throw CodecError("richonline_combat_bridge_stale");
    const bool committed=ledger_->commit_batch(updates,[&]() noexcept {
        if(!ready()) return false;
        // All checks and allocations occurred before this callback. The room
        // serialization excludes mutations between the checks and these swaps.
        const bool property_done=property_->commit_combat(prepared_property);
        const bool ground_done=ground_->commit_prepared(prepared_ground);
        if(!property_done || !ground_done) std::terminate();
        cards_->commit_inventory(after_inventory);
        for(const auto& ref:refs) {
            const auto& actor=*plan.after.actors[ref.slot];*ref.status=actor.status;
            if(ref.active) *ref.active=actor.active;
        }
        revision_=plan.after.revision;last_day_=plan.after.mines.last_day;return true;
    });
    if(!committed) throw CodecError("richonline_combat_bridge_stale");
    for(const auto& detail:impact_logs) log(detail);
    return {std::move(plan.packets),std::move(plan.bankrupt_actors)};
}
RichonlineCombatBridgeResult RichonlineCombatBridge::boss_turn(std::span<const RichonlineCombatActorRef> refs,
    std::uint8_t boss,const RichonlineBossAttackRandomness& random,const std::function<void(const std::string&)>& log) {
    const auto before=snapshot(refs);
    return apply(refs,before,prepare_richonline_boss_combat_turn(before.combat,world_,boss,random,policy_),nullptr,log);
}
RichonlineCombatBridgeResult RichonlineCombatBridge::finish_round(std::span<const RichonlineCombatActorRef> refs,std::uint64_t day) {
    const auto before=snapshot(refs);
    return apply(refs,before,prepare_richonline_combat_mine_day(before.combat,world_,day,true));
}
RichonlineCombatBridgeResult RichonlineCombatBridge::missile_base_round(std::span<const RichonlineCombatActorRef> refs,
    std::uint64_t round,const std::function<std::size_t(std::size_t)>& random,
    const std::function<void(const std::string&)>& log) {
    const auto clock=property_->prepare_missile_round(round);
    if(!clock) return {};
    const auto before=snapshot(refs);
    auto plan=prepare_richonline_missile_base_round(before.combat,world_,clock->salvos(),random);
    const auto volleys=std::move(plan.base_volleys);
    auto result=apply(refs,before,std::move(plan),&*clock,log);
    if(log) for(const auto& [property,remaining]:clock->clocks()) if(remaining)
        log("richonline_missile_base_clock round="+std::to_string(round)+" property="+
            std::to_string(property)+" remaining="+std::to_string(remaining));
    if(log) for(const auto& volley:volleys) {
        auto detail="richonline_missile_base_fired round="+std::to_string(round)+
            " property="+std::to_string(volley.salvo.property)+" owner="+std::to_string(volley.salvo.owner)+
            " level="+std::to_string(volley.salvo.level)+" target_kind="+std::to_string(static_cast<unsigned>(volley.salvo.target))+
            " requested="+std::to_string(volley.salvo.shots)+" fired="+std::to_string(volley.targets.size())+
            " controlled="+std::to_string(volley.controlled)+
            " policy=uniform-live-targets-skip-empty-v1";
        for(const auto target:volley.targets) detail+=" target="+std::to_string(target);
        log(detail);
    }
    return result;
}
struct RichonlineCombatBridge::PreparedHumanAttack::Data {
    const RichonlineCombatBridge* owner;
    Snapshot before;
    RichonlineCombatTurnPlan plan;
    bool consumed=false;
};
RichonlineCombatBridge::PreparedHumanAttack::PreparedHumanAttack(std::shared_ptr<Data> data)
    :data_(std::move(data)) {}
const std::vector<Bytes>& RichonlineCombatBridge::PreparedHumanAttack::packets() const {
    if(!data_ || data_->consumed) throw CodecError("richonline_attack_plan_consumed");
    return data_->plan.packets;
}
RichonlineCombatBridge::PreparedHumanAttack RichonlineCombatBridge::prepare_human_attack(
    std::span<const RichonlineCombatActorRef> refs,const RichonlineTargetCardRequest& request,
    std::uint16_t calendar,const RichonlineBossCards::PreparedConsumption& consumption) const {
    auto before=snapshot(refs);
    auto plan=prepare_richonline_combat_human_card(before.combat,world_,0,request,calendar,consumption);
    return PreparedHumanAttack{std::make_shared<PreparedHumanAttack::Data>(
        PreparedHumanAttack::Data{this,std::move(before),std::move(plan),false})};
}
RichonlineCombatBridgeResult RichonlineCombatBridge::commit_human_attack(
    std::span<const RichonlineCombatActorRef> refs,PreparedHumanAttack& prepared,
    const std::function<void(const std::string&)>& log) {
    if(!prepared.data_ || prepared.data_->owner!=this || prepared.data_->consumed)
        throw CodecError("richonline_attack_plan_owner_or_consumed");
    // 即使提交被快照校验拒绝，也不能复用已经移动过内容的计划再次扣卡。
    auto& data=*prepared.data_;data.consumed=true;
    return apply(refs,data.before,std::move(data.plan),nullptr,log);
}
RichonlineCombatBridgeResult RichonlineCombatBridge::human_card(std::span<const RichonlineCombatActorRef> refs,
    const RichonlineTargetCardRequest& request,std::uint16_t calendar,bool recover_refusal,
    const std::function<void(const std::string&)>& log) {
    std::optional<PreparedHumanAttack> plan;
    try {
        const auto prepared=cards_->prepare_target_effect(request);
        if(!prepared) throw CodecError("richonline_combat_human_card_not_owned");
        const auto card=prepared->source_inventory[static_cast<std::size_t>(request.inventory_slot)].card_id;
        const RichonlineBossCards::PreparedConsumption consumption{prepared->source_inventory,prepared->remaining_inventory,
            request.inventory_slot,card};
        plan=prepare_human_attack(refs,request,calendar,consumption);
    } catch(const CodecError& error) {
        if(!recover_refusal) throw;
        if(log) {
            auto detail=std::string("richonline_attack_card_refused reason=")+error.what()+
                " slot="+std::to_string(request.inventory_slot);
            const auto& inventory=cards_->inventory();
            for(std::size_t index=0;index<inventory.size();++index)
                detail+=" hand["+std::to_string(index)+"]="+std::to_string(inventory[index].card_id)+
                    ":"+std::to_string(inventory[index].count);
            log(detail);
        }
        return {{encode_richonline_dice_recovery400b(game_)},{}};
    }
    return commit_human_attack(refs,*plan,log);
}
bool RichonlineCombatBridge::has_mine(std::int16_t position) const {
    const auto snapshot=ground_->snapshot();const auto found=snapshot.objects.find(position);
    return found!=snapshot.objects.end() && (found->second.npc==12 || found->second.npc==27);
}
RichonlineCombatBridgeResult RichonlineCombatBridge::detonate_card(std::span<const RichonlineCombatActorRef> refs,
    std::uint8_t slot,const std::function<void(const std::string&)>& log) {
    const auto before=snapshot(refs);
    std::optional<RichonlineCombatTurnPlan> plan;
    try {
        const auto consumption=cards_->prepare_consumption(static_cast<std::int8_t>(slot),501);
        if(!consumption) throw CodecError("richonline_detonation_card_not_owned");
        plan=prepare_richonline_combat_detonate(before.combat,world_,0,*consumption);
    } catch(const CodecError& error) {
        if(log) log(std::string("richonline_detonation_refused reason=")+error.what());
        return {{encode_richonline_dice_recovery400b(game_)},{}};
    }
    return apply(refs,before,std::move(*plan));
}
RichonlineCombatBridgeResult RichonlineCombatBridge::stepped_mine(std::span<const RichonlineCombatActorRef> refs,
    std::int16_t root,bool notify_client) {
    const auto before=snapshot(refs);
    return apply(refs,before,prepare_richonline_combat_stepped_mine(before.combat,world_,root,notify_client));
}
RichonlineCombatBridgeResult RichonlineCombatBridge::timed_bomb_card(std::span<const RichonlineCombatActorRef> refs,
    std::uint8_t actor,const RichonlineTimedBombRequest110& request,std::uint16_t calendar,
    const RichonlineTimedBombRules& rules,const RichonlineTimedBombEligibility& raw,std::uint8_t opaque,
    const std::function<void(const std::string&)>& log) {
    // This BOSS bridge owns the shared human hand only; other actor hands need
    // an explicit inventory authority before they can consume this card.
    if(actor!=0) throw CodecError("richonline_timed_bomb_bridge_inventory_actor_invalid");
    const auto before=snapshot(refs);
    std::optional<RichonlineCombatTurnPlan> plan;
    try {
        const auto consumption=cards_->prepare_consumption(request.inventory_slot,1045);
        if(!consumption) throw CodecError("richonline_timed_bomb_card_not_owned");
        plan=prepare_richonline_timed_bomb_card(before.combat,world_,actor,request,calendar,rules,raw,*consumption,opaque);
    } catch(const CodecError& error) {
        if(log) log(std::string("richonline_timed_bomb_card_refused reason=")+error.what());
        return {{encode_richonline_dice_recovery400b(game_)},{}};
    }
    return apply(refs,before,std::move(*plan));
}
RichonlineCombatBridgeResult RichonlineCombatBridge::fire_landing(std::span<const RichonlineCombatActorRef> refs,
    std::uint8_t victim,std::int16_t position,std::uint32_t base,const std::function<void()>& preflight) {
    const auto before=snapshot(refs);
    const auto found=before.ground.objects.find(position);
    if(found==before.ground.objects.end() || found->second.npc!=26 || !preflight ||
        (found->second.byte7!=255 && found->second.byte7>=2))
        throw CodecError("richonline_combat_fire_ground_invalid");
    const auto owner=found->second.byte7==255?std::int8_t{-1}:static_cast<std::int8_t>(found->second.byte7);
    auto plan=prepare_richonline_combat_fire_landing(before.combat,world_,owner,victim,position,base);
    if(plan.bankrupt_actors.empty()) preflight();
    return apply(refs,before,std::move(plan));
}
RichonlineCombatBridgeResult RichonlineCombatBridge::poison_card(std::span<const RichonlineCombatActorRef> refs,
    const RichonlineResearchCardRequest& request,const RichonlineResearchCardContext& context,std::uint32_t& count,
    const RichonlinePoisonRules& rules,std::span<const RichonlinePoisonCell> footprint,
    std::span<const RichonlineRawActorState> raw,std::span<std::array<std::uint8_t,8>> relations,
    bool recover_refusal,const std::function<void(const std::string&)>& log) {
    if(context.actor!=0 || relations.size()!=2) throw CodecError("richonline_poison_bridge_actor_invalid");
    const auto before=snapshot(refs);const auto expected_count=count;
    const std::array expected_relations{relations[0],relations[1]};
    std::optional<RichonlineCombatPoisonPlan> planned;
    try {
        planned=prepare_richonline_combat_poison(before.combat,world_,request,context,count,rules,footprint,raw);
    } catch(const CodecError& error) {
        if(!recover_refusal) throw;
        if(log) log(std::string("richonline_poison_refused reason=")+error.what());
        return {{encode_richonline_dice_recovery400b(game_)},{}};
    }
    auto& plan=*planned;
    auto after_relations=expected_relations;
    for(const auto victim:plan.hit_actors) {
        if(victim>=after_relations.size()) throw CodecError("richonline_poison_bridge_victim_invalid");
        if(static_cast<std::int8_t>(after_relations[0][victim])>0) {
            after_relations[0][victim]=0;after_relations[victim][0]=0;
        }
    }
    if(count!=expected_count || relations[0]!=expected_relations[0] || relations[1]!=expected_relations[1])
        throw CodecError("richonline_poison_bridge_stale");
    auto result=apply(refs,before,std::move(plan.combat));
    // No fallible work after the shared commit. This serialized owner owns the
    // counter and relation arrays alongside the stores validated by apply.
    count=plan.after_use_count;relations[0]=after_relations[0];relations[1]=after_relations[1];
    return result;
}
RichonlineCombatBridgeResult RichonlineCombatBridge::timed_bomb_step(std::span<const RichonlineCombatActorRef> refs,
    const RichonlineTimedBombStepContext& context,const std::optional<RichonlineMoveCountdown12>& ack,
    std::uint16_t calendar,RichonlineTimedBombContinuationPolicy policy) {
    const auto before=snapshot(refs);
    auto plan=prepare_richonline_timed_bomb_step(before.combat,world_,context,policy);
    if(plan.outcome==RichonlineTimedBombStepOutcome::exploded) {
        if(!ack) throw CodecError("richonline_timed_bomb_explosion_ack_missing");
        validate_richonline_timed_bomb_ack12(plan,*ack,calendar);
    } else if(ack) throw CodecError("richonline_timed_bomb_ack_without_explosion");
    if(plan.outcome==RichonlineTimedBombStepOutcome::unchanged) return {};
    return apply(refs,before,std::move(plan.combat));
}
struct RichonlineCombatBridge::PreparedTimedBombSegment::Data {
    const RichonlineCombatBridge* owner;
    Snapshot before;
    RichonlineTimedBombSegmentPlan plan;
    std::uint16_t calendar;
};
RichonlineCombatBridge::PreparedTimedBombSegment::PreparedTimedBombSegment(std::shared_ptr<Data> data)
    :data_(std::move(data)) {}
const RichonlineTimedBombSegmentPlan& RichonlineCombatBridge::PreparedTimedBombSegment::plan() const {
    if(!data_) throw CodecError("richonline_timed_bomb_segment_token_invalid");
    return data_->plan;
}
bool RichonlineCombatBridge::PreparedTimedBombSegment::committed() const noexcept {
    return data_ && data_->plan.combat.committed;
}
RichonlineCombatBridge::PreparedTimedBombSegment RichonlineCombatBridge::prepare_timed_bomb_segment(
    std::span<const RichonlineCombatActorRef> refs,std::uint8_t mover,
    std::span<const RichonlineTimedBombStepContext> steps,std::uint16_t calendar,
    RichonlineTimedBombContinuationPolicy policy) const {
    auto before=snapshot(refs);
    auto plan=prepare_richonline_timed_bomb_segment(before.combat,world_,mover,steps,policy);
    // NEW7F5D90 consumes roadblocks and bananas after bomb handling. Only acknowledged
    // completed steps reach this atomic ground update; later route objects stay.
    for(std::size_t index=0;index<plan.accepted_steps;++index)
        std::erase_if(plan.combat.after.dynamic_npcs,[position=steps[index].actual_position](const auto& npc) {
            return npc.position==position && (npc.type==30 || npc.type==11);
        });
    return PreparedTimedBombSegment(std::make_shared<PreparedTimedBombSegment::Data>(
        PreparedTimedBombSegment::Data{this,std::move(before),std::move(plan),calendar}));
}
RichonlineCombatBridgeResult RichonlineCombatBridge::commit_timed_bomb_segment(
    std::span<const RichonlineCombatActorRef> refs,PreparedTimedBombSegment& prepared,
    const std::optional<RichonlineMoveCountdown12>& ack) {
    if(!prepared.data_ || prepared.data_->owner!=this)
        throw CodecError("richonline_timed_bomb_segment_token_invalid");
    auto& data=*prepared.data_;
    if(data.plan.combat.committed) throw CodecError("richonline_timed_bomb_segment_already_committed");
    if(data.plan.exploding_owner) {
        if(!ack) throw CodecError("richonline_timed_bomb_explosion_ack_missing");
        validate_richonline_timed_bomb_segment_ack12(data.plan,*ack,data.calendar);
    } else if(ack) throw CodecError("richonline_timed_bomb_ack_without_explosion");
    std::array<bool,8> seen{};
    if(refs.size()!=2) throw CodecError("richonline_combat_bridge_actors_invalid");
    for(const auto& ref:refs) {
        if(ref.slot>=8 || !data.before.combat.actors[ref.slot] || seen[ref.slot])
            throw CodecError("richonline_combat_bridge_actor_invalid");
        seen[ref.slot]=true;
    }
    // apply compares against the ORIGINAL positions/status/funds/ground; the
    // projected positions are returned to the route owner, never stored here.
    auto result=apply(refs,data.before,data.plan.combat);
    data.plan.combat.committed=true;return result;
}
}
