#include "richonline_boss_turns.hpp"
#include "richonline_boss_cards.hpp"
#include "richonline_property_wire.hpp"
#include "richonline_construction_wire.hpp"
#include "richonline_junction.hpp"
#include "richonline_game_bank.hpp"
#include "richonline_game_ledger.hpp"
#include "richonline_motion_card.hpp"
#include "richonline_fixed_step_card.hpp"
#include "richonline_cosmetic_card.hpp"
#include "richonline_npc_session.hpp"
#include "richonline_collision.hpp"
#include "richonline_combat_bridge.hpp"
#include "richonline_portal_landing.hpp"
#include "richonline_ground_card.hpp"
#include "richonline_route_effect.hpp"
#include "richonline_clear_card.hpp"
#include "richonline_research_cards.hpp"
#include "richonline_boss_landing.hpp"
#include "richonline_boss_property.hpp"
#include <limits>
#include <chrono>

#include <iterator>
#include <algorithm>
#include <utility>
#include <type_traits>

namespace richnet {
namespace {
enum class Phase { loading, roll, frozen, jailed, jail_exit, moving, stationary, bank, npc, landing, junction, finished, closed };
struct Turns {
    RichonlineBoardInit init;
    RichonlineRoadTopology topology;
    RichonlineBossTurnRules rules;
    Phase phase = Phase::loading;
    std::uint8_t actor = 1; // 当前策略由 BOSS 先手，BOSS 固定使用槽位 1。
    RichonlineRoute route;
    std::uint32_t game_mode;
    struct Decision { std::uint16_t counter,opcode; };
    std::optional<Decision> pending_decision{};
    std::vector<Decision> retired_decisions{};
    std::optional<RichonlineJunction> junction{};
    std::uint16_t landing_counter = 0;
    std::size_t checkpoint_cursor = 0;
    std::optional<RichonlineGameFundsSnapshot> bank_funds{};
    std::optional<std::size_t> bank_checkpoint{};
    std::array<RichonlineActorStatus,2> status{};
    std::uint16_t active_counter=0;
    std::uint64_t turn_sequence=0;
    struct PaidMove { std::uint16_t counter; std::uint8_t die; };
    std::optional<PaidMove> accepted_paid_move{};
    struct PendingLanding { std::int16_t position; std::uint8_t heading; std::uint16_t counter; bool sent_stop; };
    std::optional<PendingLanding> npc_landing{};
    std::array<std::uint64_t,2> actor_turns{};
    std::uint64_t complete_rounds=0;
    std::optional<std::chrono::sys_days> chongyang_awarded_day{};
    std::optional<std::chrono::steady_clock::time_point> npc_deadline{};
    std::optional<std::uint16_t> npc_pending_counter{},npc_retired_counter{};
    std::array<bool,2> active{true,true};
    std::array<std::optional<std::uint32_t>,2> attack_building_source{},defense_building_source{};
    std::optional<std::uint64_t> pending_mine_day{};
    std::optional<std::chrono::steady_clock::time_point> controlled_roll_deadline{};
    struct ControlledMove { std::uint16_t counter; };
    std::optional<ControlledMove> accepted_controlled_move{};
    // Number of already authenticated completed steps in the immutable4011.
    // Bank responses advance their own animation cursor, not this authority.
    std::size_t authenticated_steps=0;
    struct RetiredBombStop {std::uint16_t counter;std::int16_t position;std::uint64_t turn;};
    std::vector<RetiredBombStop> retired_bomb_stops{};
    // NEW7F3840 explicitly clears actor1472[8] at construction. All relation
    // mutations supported by this owner use this array (not a per-request default).
    std::array<std::array<std::uint8_t,8>,2> relations1472{};
    std::optional<std::chrono::steady_clock::time_point> frozen_deadline{};
    std::optional<std::chrono::steady_clock::time_point> jail_deadline{};
    std::optional<Decision> retired_jail_exit{};
    std::optional<std::uint64_t> retired_jail_exit_turn{};
    struct AcceptedHibernate { std::array<std::uint8_t,6> request; std::uint64_t turn; };
    std::optional<AcceptedHibernate> accepted_hibernate{};
    std::uint8_t human_dice_count=1;
    struct AcceptedRandomRoll { std::uint16_t counter; std::uint64_t turn; };
    std::optional<AcceptedRandomRoll> accepted_random_roll{};
    std::uint32_t poison_use_count=0;

    bool controlled_roll_actor() const noexcept {
        return status[actor].possession==7 || status[actor].sleepwalking!=0;
    }
    void require_local_controls() const {
        if(phase==Phase::roll && actor==init.local_slot && controlled_roll_actor())
            throw CodecError("richonline_boss_controlled_action_forbidden");
    }
    void await_roll() {
        phase=Phase::roll;
        controlled_roll_deadline=controlled_roll_actor() ?
            std::optional{rules.now()+rules.controlled_roll_timeout} : std::nullopt;
    }

    std::array<RichonlineCombatActorRef,2> combat_refs(std::optional<std::int16_t> current_position={}) {
        std::array<RichonlineCombatActorRef,2> refs{};
        for(std::uint8_t slot=0;slot<refs.size();++slot) {
            auto capabilities=rules.combat_capabilities(slot,status[slot]);capabilities.active=active[slot];
            if(rules.raw_authority) {
                const auto& raw=rules.raw_authority->actor(slot);
                capabilities.in_hospital=raw.hospital1494 && *raw.hospital1494!=-1;
                capabilities.in_prison=raw.jail1495 && *raw.jail1495!=-1;
            }
            refs[slot]={slot,current_position && slot==actor ? *current_position : init.participants[slot].position,
                &status[slot],capabilities,&active[slot],&attack_building_source[slot],&defense_building_source[slot]};
        }
        return refs;
    }
    std::vector<Bytes> terminal(std::vector<Bytes> messages,std::vector<std::uint8_t> bankrupt,
        RichonlineTerminalReason reason) {
        if(!rules.terminal || (bankrupt.empty() && reason!=RichonlineTerminalReason::month_limit))
            throw CodecError("richonline_boss_terminal_required");
        if(reason==RichonlineTerminalReason::month_limit && !bankrupt.empty())
            throw CodecError("richonline_month_limit_elimination_invalid");
        for(const auto slot:bankrupt) {
            if(slot>=active.size()) throw CodecError("richonline_boss_bankrupt_actor_invalid");
            active[slot]=false;
        }
        auto result=rules.terminal({std::move(bankrupt),reason,game_mode,actor,active_counter,turn_sequence});
        // This owner has exactly one human and one BOSS. Partial elimination in
        // a future multi-BOSS owner must be handled there, not falsely resumed.
        if(!result.closed) throw CodecError("richonline_boss_terminal_not_closed");
        messages.insert(messages.end(),std::make_move_iterator(result.messages.begin()),
            std::make_move_iterator(result.messages.end()));
        phase=Phase::finished;route={};npc_landing.reset();npc_deadline.reset();npc_pending_counter.reset();
        controlled_roll_deadline.reset();
        return messages;
    }

    bool supported_status(const RichonlineActorStatus& value) const {
        return value.sleepwalking<=127 && value.frozen<=127 && !value.attack_turns && !value.damage_turns &&
            value.attack_multiplier==1.0F && value.damage_multiplier==1.0F &&
            !value.protected_from_status && (!value.possession || (rules.npcs &&
                ((*value.possession>=0 && *value.possession<=3) || *value.possession==7 ||
                    (rules.npc_aura && (*value.possession==4 || *value.possession==6))))) &&
            ((!value.timed_bomb && !value.timed_bomb_owner) || (rules.timed_bombs && value.timed_bomb &&
                *value.timed_bomb>=1 && *value.timed_bomb<=127 && value.timed_bomb_owner &&
                *value.timed_bomb_owner>=-1 && *value.timed_bomb_owner<static_cast<std::int8_t>(status.size()))) &&
            value.one_step<=127 && value.six_steps<=127 && value.turtle<=127 && value.stay<=127 &&
            !(value.one_step && value.six_steps);
    }

    void retire_decision() {
        if (!pending_decision) return;
        if (!retired_decisions.empty() && retired_decisions.back().counter!=pending_decision->counter)
            retired_decisions.clear();
        retired_decisions.push_back(*pending_decision);
        pending_decision.reset();
    }
    std::vector<Bytes> advance(std::vector<Bytes> messages) {
        retire_decision();
        richonline_status_finish_previous_turn(status[actor]);
        if (actor==0) {
            ++complete_rounds;
            if(rules.combat) pending_mine_day=complete_rounds;
            if(rules.npcs) {
                auto spawned=rules.npcs->finish_round(complete_rounds);
                messages.insert(messages.end(),std::make_move_iterator(spawned.messages.begin()),
                    std::make_move_iterator(spawned.messages.end()));
            }
        }
        actor = actor == 1 ? std::uint8_t{0} : std::uint8_t{1};
        auto next=begin_turn();
        messages.insert(messages.end(),std::make_move_iterator(next.begin()),std::make_move_iterator(next.end()));
        return messages;
    }
    std::vector<Bytes> finish_junction(RichonlineJunctionResult result) {
        init.participants[actor].direction=result.heading;
        return advance({std::move(result.response)});
    }

    struct PreparedMove { RichonlineRoute route; std::vector<Bytes> messages; };
    PreparedMove prepare_move(std::optional<std::uint8_t> chosen = {},std::int32_t reserve_charge=0,
        std::optional<std::uint8_t> count_override={},std::optional<std::array<std::int8_t,3>> previous_faces={}) {
        // Explicit emulator policy: a selected controlled die overrides a persistent
        // fixed-step effect for this roll, without erasing or extending that effect.
        const auto forced=status[actor].one_step || status[actor].turtle ? std::optional<std::uint8_t>{1} :
            status[actor].six_steps ? std::optional<std::uint8_t>{6} : std::nullopt;
        if (chosen && forced && rules.log)
            rules.log("richonline_die_policy=selected_card_overrides_fixed_step actor="+std::to_string(actor));
        const auto die_choice=chosen ? chosen : forced;
        const auto count=die_choice ? std::uint8_t{1} : count_override.value_or(actor==1?rules.boss_dice_count:human_dice_count);
        std::array<std::int8_t,3> dice{1,rules.inactive_ui_dice[0],rules.inactive_ui_dice[1]};
        std::int32_t budget=0;
        for (std::uint8_t index=0;index<count;++index) {
            const auto selected=die_choice ? static_cast<std::size_t>(*die_choice-1U) : previous_faces ?
                static_cast<std::size_t>((*previous_faces)[index]-1):rules.random(6);
            if (selected>=6) throw CodecError("richonline_boss_random_out_of_range");
            dice[index]=static_cast<std::int8_t>(selected+1);
            budget+=dice[index];
        }
        const auto& person = init.participants[actor];
        auto projected_ground=rules.ground ? rules.ground->snapshot().objects : RichonlineGroundMap{};
        const auto extend=[&projected_ground](std::int16_t position,std::int32_t step,std::int32_t total) {
            const auto found=projected_ground.find(position);
            if(found==projected_ground.end() || found->second.npc!=30) return total;
            const auto effect=plan_richonline_route_step_effect({position,static_cast<std::uint8_t>(step),
                static_cast<std::uint8_t>(total),36,-1,30,true,false,false,false,true,{},
                RichonlineRouteInvestmentGate::skip});
            projected_ground.erase(found);
            return static_cast<std::int32_t>(effect.movement_budget_after);
        };
        auto proposed = build_richonline_route(topology,{person.position,person.direction,budget,{},
            !controlled_roll_actor(),static_cast<bool>(rules.bank) || controlled_roll_actor()},rules.random,extend);
        std::vector<RichonlineMoveDirection> directions;
        for (const auto value : proposed.directions) directions.push_back(static_cast<RichonlineMoveDirection>(value));
        auto wire=rules.route_wire; wire.local_reserve_charge=reserve_charge;
        auto packet = encode_richonline_route4011({init.game_server_id,person.position,count,
            dice,std::move(directions),proposed.landings.size()},wire);
        // NEW7F5D90 consumes NPC11 and sends0011 before exhausting the dice.
        // Keep4011's dice/coverage intact; authenticate only the visited prefix.
        for(std::size_t index=0;index<proposed.landings.size();++index) {
            const auto found=projected_ground.find(proposed.landings[index]);
            if(found==projected_ground.end() || found->second.npc!=11) continue;
            if(rules.log) rules.log("richonline_roadblock_route_stop actor="+std::to_string(actor)+
                " counter="+std::to_string(active_counter)+" position="+std::to_string(proposed.landings[index])+
                " accepted_steps="+std::to_string(index+1)+" planned_steps="+std::to_string(proposed.landings.size()));
            proposed.landings.resize(index+1);proposed.directions.resize(index+1);break;
        }
        return {std::move(proposed),{std::move(packet)}};
    }
    std::vector<Bytes> commit_move(PreparedMove prepared) noexcept {
        route = std::move(prepared.route);
        checkpoint_cursor=0;authenticated_steps=0;
        phase = Phase::moving;
        controlled_roll_deadline.reset();
        return std::move(prepared.messages);
    }
    std::vector<Bytes> move(std::optional<std::uint8_t> chosen = {}) {
        return commit_move(prepare_move(chosen));
    }
    std::optional<PreparedMove> prepare_random_roll(bool automatic=false) {
        auto count=status[actor].one_step || status[actor].turtle || status[actor].six_steps ?
            std::uint8_t{1}:human_dice_count;
        if(count==1) return prepare_move();
        const auto requested=count;
        const auto free_capacity=rules.payment_equipment.dice_vehicle==RichonlineDiceVehicle::car?std::uint8_t{3}:
            rules.payment_equipment.dice_vehicle==RichonlineDiceVehicle::motorcycle?std::uint8_t{2}:std::uint8_t{1};
        const auto fallback=[&](const char* reason,std::optional<std::array<std::int8_t,3>> faces={}) {
            const auto effective=std::min(requested,free_capacity);
            if(rules.log)rules.log("richonline_automatic_dice_fallback before_count="+std::to_string(requested)+
                " effective_count="+std::to_string(effective)+" reason="+reason);
            return prepare_move({},0,effective,faces);
        };
        if(!rules.payment) {
            if(automatic)return fallback("authenticated_payment_unavailable");
            if(rules.log)rules.log("richonline_random_dice_rejected reason=authenticated_payment_unavailable");
            return {};
        }
        if(automatic) {
            const auto reserve=rules.payment->reserve();
            while(count>1 && static_cast<std::uint32_t>(rules.payment->quote_random_dice(count,rules.payment_equipment))>reserve)
                --count;
            if(count!=requested && rules.log)rules.log("richonline_automatic_dice_fallback before_count="+
                std::to_string(requested)+" effective_count="+std::to_string(count)+" reason=insufficient_reserve");
        }
        const auto price=rules.payment->quote_random_dice(count,rules.payment_equipment);
        auto prepared=prepare_move({},price,count);
        if(price==0)return prepared;
        const auto operation=rules.payment_operation_prefix+":turn="+std::to_string(turn_sequence)+
            ":counter="+std::to_string(active_counter)+":random-dice:count="+std::to_string(count);
        const auto paid=rules.payment->random_dice(operation,count,rules.payment_equipment);
        switch(paid.status) {
        case RichonlinePaymentStatus::committed:return prepared;
        case RichonlinePaymentStatus::duplicate:
        case RichonlinePaymentStatus::recovery_required:
            throw CodecError("richonline_boss_random_dice_recovery_required");
        case RichonlinePaymentStatus::insufficient_reserve:
        case RichonlinePaymentStatus::account_refused:
            if(automatic) {
                const auto& packet=prepared.messages.front();
                return fallback(paid.status==RichonlinePaymentStatus::account_refused?"account_refused":"reserve_changed",
                    std::array<std::int8_t,3>{static_cast<std::int8_t>(packet[8]),static_cast<std::int8_t>(packet[9]),
                        static_cast<std::int8_t>(packet[10])});
            }
            return {};
        }
        throw CodecError("richonline_boss_random_dice_result_invalid");
    }
    std::vector<Bytes> random_move() {
        std::vector<Bytes> refused{encode_richonline_dice_recovery400b(init.game_server_id)};
        auto prepared=prepare_random_roll();
        if(!prepared) return refused;
        accepted_random_roll=AcceptedRandomRoll{active_counter,turn_sequence};
        return commit_move(std::move(*prepared));
    }
    std::vector<Bytes> controlled_move() {
        std::vector<Bytes> refused{encode_richonline_dice_recovery400b(init.game_server_id)};
        auto proposed=prepare_random_roll(true);
        if(!proposed) {
            controlled_roll_deadline=rules.now()+rules.controlled_roll_timeout;
            return refused;
        }
        auto prepared=std::move(*proposed);
        // The route owner keeps the accepted path. Late0010 is validated
        // against this calendar and never rerolls or pays a second time.
        accepted_controlled_move=ControlledMove{active_counter};
        return commit_move(std::move(prepared));
    }
    std::vector<Bytes> playable_turn(std::vector<Bytes> messages) {
        if(actor==1 && rules.combat) {
            auto refs=combat_refs();auto attack=rules.combat->boss_turn(refs,actor,rules.combat_random());
            messages.insert(messages.end(),std::make_move_iterator(attack.packets.begin()),
                std::make_move_iterator(attack.packets.end()));
            if(!attack.bankrupt_actors.empty())
                return terminal(std::move(messages),std::move(attack.bankrupt_actors),RichonlineTerminalReason::boss_attack);
        }
        messages.push_back(encode_richonline_empty_turn420f(init.game_server_id));
        if(status[actor].stay) {
            route={};checkpoint_cursor=0;phase=Phase::stationary;
        } else if(actor==1) {
            auto movement=move();
            messages.insert(messages.end(),std::make_move_iterator(movement.begin()),std::make_move_iterator(movement.end()));
        } else await_roll();
        return messages;
    }
    std::vector<Bytes> finish_jail_exit() {
        if(phase!=Phase::jail_exit || !rules.raw_authority || !topology.jail_positions())
            throw CodecError("richonline_jail_exit_state_invalid");
        const auto entry=(*topology.jail_positions())[0],exit=(*topology.jail_positions())[1];
        const auto dx=exit%static_cast<std::int16_t>(topology.width())-entry%static_cast<std::int16_t>(topology.width());
        const auto dy=exit/static_cast<std::int16_t>(topology.width())-entry/static_cast<std::int16_t>(topology.width());
        const auto heading=dy>0 ? 0U : dx<0 ? 1U : dy<0 ? 2U : 3U;
        rules.raw_authority->exit_jail(actor);
        init.participants[actor].position=exit;
        init.participants[actor].direction=static_cast<std::uint8_t>(heading);
        jail_deadline.reset();
        if(actor==init.local_slot) {
            retired_jail_exit=Decision{active_counter,21};retired_jail_exit_turn=turn_sequence;
        }
        return playable_turn({});
    }
    std::vector<Bytes> begin_turn() {
        // NEW7C0C50 clears game+60 at entry, including resumed turn phases.
        // Supported card restore-action paths do not call that entry again.
        poison_use_count=0;
        ++active_counter;
        ++turn_sequence;
        // NEW7D87B0 resets elapsed days to zero;7D8810 counts the first
        // anchor without advancing its date.7D6CE0 expires strictly after N.
        if(actor==1 && rules.month_limit_days && complete_rounds+1>rules.month_limit_days) {
            if(rules.log) rules.log("richonline_boss_month_limit elapsed_days="+std::to_string(complete_rounds+1)+
                " limit_days="+std::to_string(rules.month_limit_days)+" policy=native-unfinished-boss-month-limit-loss-v1");
            return terminal({encode_richonline_turn4010({init.game_server_id,1,1,0},rules.opaque_turn7)},
                {},RichonlineTerminalReason::month_limit);
        }
        if(actor==1 && rules.ledger) {
            const std::chrono::year_month_day start{std::chrono::year{init.year},
                std::chrono::month{init.month},std::chrono::day{init.day}};
            const auto game_day=std::chrono::sys_days{start}+std::chrono::days{complete_rounds};
            const std::chrono::year_month_day date{game_day};
            const auto year=static_cast<int>(date.year());
            if(year>=2004 && year<2035 && chongyang_awarded_day!=game_day) {
                const auto& feast=rules.chongyang_dates[static_cast<std::size_t>(year-2004)];
                if(static_cast<unsigned>(date.month())==feast[0] &&
                    static_cast<unsigned>(date.day())==feast[1]) {
                    std::vector<RichonlineGameFundsUpdate> updates;
                    for(std::uint8_t slot=0;slot<active.size();++slot) if(active[slot]) {
                        const auto before=rules.ledger->snapshot(slot);
                        auto after=before.funds;
                        if(after.tickets>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()-99))
                            throw CodecError("richonline_feast_ticket_overflow");
                        after.tickets+=99;
                        updates.push_back({slot,before,after});
                    }
                    if(!updates.empty() && !rules.ledger->commit_batch(updates,[]{return true;}))
                        throw CodecError("richonline_feast_ledger_rejected");
                    chongyang_awarded_day=game_day;
                    if(rules.log) {
                        std::string detail="richonline_feast_chongyang date="+std::to_string(year)+"-"+
                            std::to_string(static_cast<unsigned>(date.month()))+"-"+
                            std::to_string(static_cast<unsigned>(date.day()))+" grant=99";
                        for(const auto& update:updates)
                            detail+=" actor="+std::to_string(update.actor)+" before="+
                                std::to_string(update.before.funds.tickets)+" after="+
                                std::to_string(update.after.tickets);
                        rules.log(detail);
                    }
                }
            }
        }
        if(retired_jail_exit_turn && turn_sequence-*retired_jail_exit_turn>2) {
            retired_jail_exit.reset();retired_jail_exit_turn.reset();
        }
        jail_deadline.reset();
        if(rules.raw_authority) static_cast<void>(rules.raw_authority->apply_verified_actor_timer_phase(actor,turn_sequence));
        for(std::uint8_t other=0;other<active.size();++other)
            if(static_cast<std::int8_t>(relations1472[actor][other])>0) --relations1472[actor][other];
        if(rules.research_turn_started) rules.research_turn_started(actor);
        if(accepted_random_roll && turn_sequence-accepted_random_roll->turn>2) accepted_random_roll.reset();
        frozen_deadline.reset();
        if(accepted_hibernate && turn_sequence-accepted_hibernate->turn>2) accepted_hibernate.reset();
        std::erase_if(retired_bomb_stops,[this](const auto& stop){return turn_sequence-stop.turn>2;});
        if (actor==init.local_slot) {
            accepted_paid_move.reset();accepted_controlled_move.reset();npc_retired_counter.reset();
        }
        richonline_status_begin_active_turn(status[actor]);
        if (rules.npcs) static_cast<void>(rules.npcs->actor_begin(actor,++actor_turns[actor],status[actor]));
        std::vector<Bytes> messages{
            encode_richonline_turn4010({init.game_server_id,static_cast<std::int8_t>(actor),1,0},rules.opaque_turn7)};
        if(status[actor].possession==4 || status[actor].possession==6) {
            if(!rules.npc_aura || !rules.npc_aura_raw_actor || !rules.ledger || !rules.terminal)
                throw CodecError("richonline_boss_npc_aura_capability_required");
            std::array<RichonlineNpcAuraActor,2> targets{};
            for(std::uint8_t slot=0;slot<targets.size();++slot)
                targets[slot]={slot,init.participants[slot].position,active[slot],
                    rules.npc_aura_raw_actor(slot),rules.ledger->snapshot(slot)};
            auto aura=plan_richonline_npc_aura(topology,*rules.npc_aura,
                {game_mode,actor,1,status[actor].possession,
                    RichonlineNpcAuraEffect{status[actor].possession_strength1740,status[actor].possession_multiplier1744}},targets);
            if(!aura.updates.empty() && !rules.ledger->commit_batch(aura.updates,[]{return true;}))
                throw CodecError("richonline_boss_npc_aura_ledger_rejected");
            if(!aura.bankrupt_actors.empty())
                return terminal(std::move(messages),std::move(aura.bankrupt_actors),RichonlineTerminalReason::npc_aura);
        }
        if(rules.fire_traps) {
            const auto tick=plan_richonline_fire_trap_tick(rules.ground->snapshot(),actor,actor==1,active);
            auto ground=rules.ground->prepare(tick.expected_ground,tick.after_ground);
            if(!rules.ground->commit_prepared(ground)) throw CodecError("richonline_boss_fire_clock_stale");
        }
        if(actor==1 && rules.combat) {
            if(pending_mine_day) {
                auto refs=combat_refs();auto expiry=rules.combat->finish_round(refs,*pending_mine_day);
                pending_mine_day.reset();
                messages.insert(messages.end(),std::make_move_iterator(expiry.packets.begin()),
                    std::make_move_iterator(expiry.packets.end()));
                if(!expiry.bankrupt_actors.empty())
                    return terminal(std::move(messages),std::move(expiry.bankrupt_actors),RichonlineTerminalReason::mine_day);
            }
        }
        if(rules.raw_authority) {
            const auto& raw=rules.raw_authority->actor(actor);
            if(raw.jail1495 && *raw.jail1495!=-1) {
                if(!topology.jail_positions()) throw CodecError("richonline_jail_positions_missing");
                phase=*raw.jail1495==0 ? Phase::jail_exit : Phase::jailed;
                route={};checkpoint_cursor=0;authenticated_steps=0;controlled_roll_deadline.reset();
                // The human sends0015 (decimal21) after animation12. Synthetic actors have
                // no sender, so their animation continuation uses a room timer.
                if(phase==Phase::jailed || actor!=init.local_slot)
                    jail_deadline=rules.now()+std::chrono::milliseconds{1800};
                return messages;
            }
        }
        if(status[actor].frozen) {
            // NEW7C0C50 already decremented above, then phase4 queues6003 and
            // never sends0011. A room timer owns the continuation for either actor.
            messages.push_back(encode_richonline_empty_turn420f(init.game_server_id));
            phase=Phase::frozen;route={};checkpoint_cursor=0;authenticated_steps=0;
            controlled_roll_deadline.reset();
            frozen_deadline=rules.now()+std::chrono::milliseconds{1800};
            return messages;
        }
        return playable_turn(std::move(messages));
    }
    std::vector<Bytes> opening() {
        if (phase != Phase::loading) throw CodecError("richonline_boss_duplicate_opening");
        const std::array<std::int16_t,2> starts{init.participants[0].position,init.participants[1].position};
        auto messages=rules.npcs ? rules.npcs->initial(starts).messages : std::vector<Bytes>{};
        auto next=begin_turn();
        messages.insert(messages.end(),std::make_move_iterator(next.begin()),std::make_move_iterator(next.end()));
        return messages;
    }
    std::vector<Bytes> resolve(RichonlineLandingResult result) {
        if(result.temple_change) {
            if(!rules.npcs || result.status_change || result.progress!=RichonlineLandingProgress::complete ||
                status[actor]!=result.temple_change->expected || (result.temple_change->summon &&
                    (*result.temple_change->summon==4 || *result.temple_change->summon==6) &&
                    (!rules.npc_aura || !rules.npc_aura_raw_actor || !rules.ledger || !rules.terminal)))
                throw CodecError("richonline_boss_temple_transition_invalid");
            if(result.temple_change->summon && *result.temple_change->summon>=0 && *result.temple_change->summon<4) {
                auto summon=rules.npcs->temple_summon(landing_context(init.participants[actor].position),
                    landing_counter,*result.temple_change->summon,status[actor]);
                retire_decision();
                result.messages.insert(result.messages.end(),std::make_move_iterator(summon.messages.begin()),
                    std::make_move_iterator(summon.messages.end()));
                summon.messages=std::move(result.messages);
                return npc_result(std::move(summon));
            }
            auto change=rules.npcs->prepare_temple_change(actor,*result.temple_change);
            if(!rules.npcs->commit_status_change(change,status[actor]))
                throw CodecError("richonline_boss_temple_clock_changed");
        }
        if (result.status_change) {
            if (status[actor]!=result.status_change->expected)
                throw CodecError("richonline_boss_landing_status_changed");
            if (!supported_status(result.status_change->updated))
                throw CodecError("richonline_boss_landing_status_unimplemented");
            if(rules.npcs) {
                auto change=rules.npcs->prepare_status_change(actor,status[actor],result.status_change->updated);
                if(!rules.npcs->commit_status_change(change,status[actor]))
                    throw CodecError("richonline_boss_landing_npc_status_changed");
            } else status[actor]=result.status_change->updated;
        }
        switch (result.progress) {
        case RichonlineLandingProgress::await_event:
            if(actor==init.local_slot && result.pending_opcode &&
                (!pending_decision || pending_decision->counter!=landing_counter ||
                    pending_decision->opcode!=*result.pending_opcode)) {
                retire_decision();
                pending_decision=Decision{landing_counter,*result.pending_opcode};
            }
            phase = Phase::landing;
            break;
        case RichonlineLandingProgress::complete: {
            retire_decision();
            const auto& person=init.participants[actor];
            // 当前引擎处理无状态效果的普通角色；新版 phase6 不向合成 BOSS 请求末端方向。
            if (person.lobby_identity!=-1 && !controlled_roll_actor() && junction->begin(topology,
                    {person.position,person.direction,landing_counter},rules.now())) {
                phase=Phase::junction;
                pending_decision=Decision{landing_counter,0x34};
                break;
            }
            return advance(std::move(result.messages));
        }
        case RichonlineLandingProgress::finished: phase = Phase::finished; break;
        }
        return std::move(result.messages);
    }
    std::vector<Bytes> poll() {
        if((phase==Phase::jailed || phase==Phase::jail_exit) && jail_deadline) {
            if(rules.now()<*jail_deadline) return {};
            jail_deadline.reset();
            return phase==Phase::jail_exit ? finish_jail_exit() : advance({});
        }
        if(phase==Phase::frozen) {
            if(!frozen_deadline) throw CodecError("richonline_boss_frozen_deadline_missing");
            if(rules.now()<*frozen_deadline) return {};
            frozen_deadline.reset();return advance({});
        }
        if(phase==Phase::roll && controlled_roll_deadline && rules.now()>=*controlled_roll_deadline) {
            if(actor!=init.local_slot || !controlled_roll_actor())
                throw CodecError("richonline_boss_controlled_roll_state_changed");
            if(rules.log) rules.log("richonline_controlled_roll_recovered actor="+std::to_string(actor)+
                " counter="+std::to_string(active_counter)+" policy=server_timeout_ordinary_roll");
            return controlled_move();
        }
        if(phase==Phase::npc && npc_deadline && rules.now()>=*npc_deadline && rules.npcs->awaiting_roulette())
            return npc_result(rules.npcs->resolve_roulette(actor,status[actor]));
        if (phase==Phase::bank) {
            auto result=rules.bank->poll();
            return result ? bank_result(std::move(*result)) : std::vector<Bytes>{};
        }
        if (phase==Phase::junction) {
            auto result=junction->poll(rules.now());
            return result ? finish_junction(std::move(*result)) : std::vector<Bytes>{};
        }
        if (phase != Phase::landing || !rules.poll) return {};
        auto result = rules.poll();
        return result ? resolve(std::move(*result)) : std::vector<Bytes>{};
    }
    bool retired(View plain) const {
        if (phase == Phase::closed || plain.size() < 4) return false;
        const auto opcode=read_le(plain.first(2));
        if(opcode==164 && accepted_hibernate && plain.size()==accepted_hibernate->request.size() &&
            std::equal(plain.begin(),plain.end(),accepted_hibernate->request.begin())) return true;
        if(opcode==0x12) {
            const auto request=std::get<RichonlineMoveCountdown12>(parse_richonline_movement_request(plain));
            for(const auto& stop:retired_bomb_stops)
                if(request.calendar_counter==stop.counter && request.endpoint==stop.position) return true;
        }
        if(opcode==0x10 && accepted_controlled_move) {
            const auto request=std::get<RichonlineMoveRequest10>(parse_richonline_movement_request(plain));
            if(request.calendar_counter==accepted_controlled_move->counter && request.parameter==0) return true;
        }
        if(opcode==0x10 && accepted_random_roll) {
            const auto request=std::get<RichonlineMoveRequest10>(parse_richonline_movement_request(plain));
            if(request.calendar_counter==accepted_random_roll->counter && request.parameter==0) return true;
        }
        if(opcode==34 && npc_retired_counter) {
            const auto request=decode_richonline_deity_roulette(plain);
            if(request.calendar==*npc_retired_counter) return true;
        }
        if (opcode==22 && accepted_paid_move) {
            const auto request=std::get<RichonlinePaidDiceRequest22>(parse_richonline_controlled_dice_request(plain));
            if (request.calendar_counter==accepted_paid_move->counter && request.selected_die==accepted_paid_move->die)
                return true;
        }
        for (const auto& retired_decision : retired_decisions) {
        if (read_le(plain.subspan(2,2))!=retired_decision.counter) continue;
        if (retired_decision.opcode==0x20 && opcode==0x20) {
            static_cast<void>(decode_richonline_property_request(plain));
            return true;
        }
        if (retired_decision.opcode==0x37 && opcode==0x37) {
            static_cast<void>(decode_richonline_construction_request(plain));
            return true;
        }
        if (retired_decision.opcode==0x38 && opcode==0x38) {
            static_cast<void>(decode_richonline_upgrade_request(plain));
            return true;
        }
        if (retired_decision.opcode==0x39 && opcode==0x39) {
            static_cast<void>(decode_richonline_research_request(plain));
            return true;
        }
        if (retired_decision.opcode==0x34 && opcode==0x34) {
            static_cast<void>(decode_richonline_junction_request(plain));
            return true;
        }
        if (retired_decision.opcode==0x27 && opcode==0x27) {
            static_cast<void>(decode_richonline_game_bank_request(plain));
            return true;
        }
        if (retired_decision.opcode==0x30 &&
            (((opcode==0x30 || opcode==0x31) && plain.size()==6) || (opcode==0x35 && plain.size()==4))) return true;
        }
        return false;
    }
    std::optional<std::size_t> next_bank_checkpoint() const {
        if(controlled_roll_actor()) return {};
        // The final tile uses0011/4013, never an intermediate0028.
        for (auto index=checkpoint_cursor; index+1<route.landings.size(); ++index)
            if (topology.cell(route.landings[index]).static_type==9) return index;
        return {};
    }
    std::optional<RichonlineGroundObjects::Prepared> prepare_ground_progress(std::size_t end) {
        if(!rules.ground) return {};
        if(end<authenticated_steps || end>=route.landings.size())
            throw CodecError("richonline_boss_ground_route_progress_invalid");
        const auto before=rules.ground->snapshot();auto after=before.objects;
        for(auto index=authenticated_steps;index<=end;++index) {
            const auto found=after.find(route.landings[index]);
            if(found!=after.end() && (found->second.npc==30 || found->second.npc==11)) after.erase(found);
        }
        return rules.ground->prepare(before,after);
    }
    void commit_ground_progress(RichonlineGroundObjects::Prepared& prepared,std::size_t end) {
        if(!rules.ground->commit_prepared(prepared)) throw CodecError("richonline_boss_ground_route_stale");
        authenticated_steps=end+1;
    }
    RichonlineTimedBombStepContext timed_context(std::int16_t position) const {
        const auto context=rules.timed_bombs->step_context(actor,position);
        if(context.moving_actor!=actor || context.actual_position!=position ||
            context.actor_count!=init.participants.size())
            throw CodecError("richonline_boss_timed_context_mismatch");
        return context;
    }
    std::optional<RichonlineCombatBridge::PreparedTimedBombSegment> prepare_timed_progress(
        std::uint16_t opcode,std::uint16_t calendar,std::int16_t reported_position) {
        if(!rules.timed_bombs) return {};
        if(calendar!=active_counter) throw CodecError("richonline_boss_movement_counter_mismatch");
        if(route.landings.empty() || authenticated_steps>=route.landings.size())
            throw CodecError("richonline_boss_timed_route_progress_invalid");
        const auto bank=next_bank_checkpoint();
        const auto end=bank.value_or(route.landings.size()-1);
        if(end<authenticated_steps) throw CodecError("richonline_boss_timed_route_progress_invalid");
        std::vector<RichonlineTimedBombStepContext> steps;steps.reserve(end-authenticated_steps+1);
        for(auto index=authenticated_steps;index<=end;++index) steps.push_back(timed_context(route.landings[index]));
        auto refs=combat_refs();
        auto prepared=rules.combat->prepare_timed_bomb_segment(refs,actor,steps,active_counter,
            RichonlineTimedBombContinuationPolicy::timed_bomb_stop_then_landing);
        const auto& result=prepared.plan();
        const auto expected_opcode=result.exploding_owner ? std::uint16_t{0x12} :
            bank ? std::uint16_t{0x28} : std::uint16_t{0x11};
        if(opcode!=expected_opcode) throw CodecError("richonline_boss_timed_checkpoint_opcode_mismatch");
        if(result.actual_stop!=reported_position) throw CodecError("richonline_boss_timed_checkpoint_position_mismatch");
        if(result.accepted_steps==0 || result.accepted_steps>steps.size())
            throw CodecError("richonline_boss_timed_route_progress_invalid");
        return prepared;
    }
    RichonlineCombatBridgeResult commit_timed_progress(RichonlineCombatBridge::PreparedTimedBombSegment& prepared,
        const std::optional<RichonlineMoveCountdown12>& ack={}) {
        const auto completed=authenticated_steps+prepared.plan().accepted_steps;
        auto refs=combat_refs();
        auto result=rules.combat->commit_timed_bomb_segment(refs,prepared,ack);
        authenticated_steps=completed;
        init.participants[actor].position=route.landings[completed-1];
        init.participants[actor].direction=route.directions[completed-1];
        return result;
    }
    std::vector<Bytes> bank_result(RichonlineGameBankResult result) {
        if (!bank_funds || result.entry.actor_slot!=actor ||
            result.entry.balance.cash!=bank_funds->funds.cash ||
            result.entry.balance.deposit!=bank_funds->funds.deposit)
            throw CodecError("richonline_boss_bank_snapshot_mismatch");
        if (result.continuation==RichonlineGameBankContinuation::await_choice) {
            phase=Phase::bank;
            return std::move(result.messages);
        }
        auto funds=bank_funds->funds;
        funds.cash=result.after.cash; funds.deposit=result.after.deposit;
        rules.ledger->commit(actor,*bank_funds,funds);
        bank_funds.reset();
        retire_decision();
        if (result.continuation==RichonlineGameBankContinuation::resume_movement) {
            if (!bank_checkpoint) throw CodecError("richonline_boss_bank_checkpoint_missing");
            checkpoint_cursor=*bank_checkpoint+1;
            bank_checkpoint.reset();
            phase=Phase::moving;
            //402A resumes the client's saved route and advances progress itself.
            return std::move(result.messages);
        }
        if (bank_checkpoint) throw CodecError("richonline_boss_bank_unexpected_checkpoint");
        return resolve({std::move(result.messages),RichonlineLandingProgress::complete});
    }
    std::vector<Bytes> open_bank(std::int16_t position,std::uint16_t counter,
        RichonlineGameBankVisit visit,std::optional<std::size_t> checkpoint={}) {
        if (!rules.bank || !rules.ledger) throw CodecError("richonline_boss_bank_unavailable");
        const auto funds=rules.ledger->snapshot(actor);
        if (!funds.funds.deposit) throw CodecError("richonline_boss_bank_deposit_unknown");
        auto result=rules.bank->begin({actor,position,counter,visit,
            {funds.funds.cash,*funds.funds.deposit},init.participants[actor].lobby_identity==-1});
        bank_funds=funds; bank_checkpoint=checkpoint;
        pending_decision=Decision{counter,0x27};
        return bank_result(std::move(result));
    }
    RichonlineLandingContext landing_context(std::int16_t position) const {
        const auto& cell=topology.cell(position);
        std::uint8_t degree=0;
        for(const auto& neighbor:cell.neighbors) if(neighbor) ++degree;
        bool occupied=false;
        for(std::size_t slot=0;slot<init.participants.size();++slot)
            if(slot!=actor && init.participants[slot].position==position) occupied=true;
        std::array<RichonlineCollisionActor,2> pair{};
        for(std::size_t slot=0;slot<pair.size();++slot)
            pair[slot]={static_cast<std::uint8_t>(slot),slot==actor ? position : init.participants[slot].position,
                true,init.participants[slot].lobby_identity==-1,false,status[slot].possession,{}};
        const auto collision_resolved=occupied && richonline_boss_collision_allows_shared_landing(game_mode,actor,pair);
        return {actor,position,cell.static_type,cell.property_ref,game_mode,
            init.participants[actor].lobby_identity==-1,degree,occupied,status[actor],collision_resolved};
    }
    void project_ice_landing(RichonlineLandingContext& context) const {
        if(!rules.ice_traps) return;
        const auto ground=rules.ground->snapshot();
        const auto found=ground.objects.find(context.position);
        if(found!=ground.objects.end() && found->second.npc==25)
            context.actor_status=plan_richonline_ice_trap_landing(context.position,ground,
                context.actor_status,*rules.ice_traps).after_status;
    }
    void consume_ice_landing(std::int16_t position) {
        if(!rules.ice_traps) return;
        const auto before=rules.ground->snapshot();
        const auto found=before.objects.find(position);
        if(found==before.objects.end() || found->second.npc!=25) return;
        const auto planned=plan_richonline_ice_trap_landing(position,before,status[actor],*rules.ice_traps);
        auto context=landing_context(position);context.actor_status=planned.after_status;
        rules.npc_landing_preflight(context);
        auto ground=rules.ground->prepare(planned.expected_ground,planned.after_ground);
        auto clock=rules.npcs ? std::optional{rules.npcs->prepare_status_change(actor,
            planned.expected_status,planned.after_status)} : std::nullopt;
        if(status[actor]!=planned.expected_status || !rules.ground->matches(ground) ||
            (clock && !rules.npcs->matches_status_change(*clock,status[actor])))
            throw CodecError("richonline_boss_ice_landing_stale");
        // Serialized room owner: both prepared commits are nonthrowing, and no
        // callback or allocation occurs between the checks and the two writes.
        if(!rules.ground->commit_prepared(ground)) std::terminate();
        if(clock) {
            if(!rules.npcs->commit_status_change(*clock,status[actor])) std::terminate();
        } else status[actor]=planned.after_status;
    }
    std::vector<Bytes> finish_landing(PendingLanding landing) {
        const auto& cell=topology.cell(landing.position);
        if (cell.static_type==9 && rules.bank && !richonline_landing_controlled(status[actor])) {
            if (cell.property_ref!=-1) throw CodecError("richonline_boss_bank_property_phase_unimplemented");
            for (std::size_t slot=0;slot<init.participants.size();++slot)
                if (slot!=actor && init.participants[slot].position==landing.position &&
                    !landing_context(landing.position).collision_resolved)
                    throw CodecError("richonline_boss_bank_collision_unimplemented");
            Bytes stop;append_le(stop,0x4013,2);append_le(stop,init.game_server_id,2);
            append_le(stop,static_cast<std::uint16_t>(landing.position),2);
            auto& person=init.participants[actor];
            person.position=landing.position;person.direction=landing.heading;
            landing_counter=landing.counter;route={};
            auto messages=open_bank(landing.position,landing.counter,RichonlineGameBankVisit::landing);
            if(!landing.sent_stop) messages.insert(messages.begin(),std::move(stop));
            return messages;
        }
        if (cell.static_type==28 || cell.static_type==58 || cell.static_type==61) {
            if (!rules.portal_landing) throw CodecError("richonline_boss_portal_authority_missing");
            const auto context=landing_context(landing.position);
            const auto portal=rules.portal_landing(context);
            if (!portal) throw CodecError("richonline_boss_portal_plan_missing");
            const auto& expected=portal->expected;
            if (expected.actor_slot!=context.actor_slot || expected.position!=context.position ||
                expected.static_type!=context.static_type || expected.property_ref!=context.property_ref ||
                expected.game_mode!=context.game_mode || expected.synthetic_actor!=context.synthetic_actor ||
                expected.road_degree!=context.road_degree ||
                expected.occupied_by_other_actor!=context.occupied_by_other_actor ||
                expected.collision_resolved!=context.collision_resolved ||
                expected.actor_status!=context.actor_status)
                throw CodecError("richonline_boss_portal_plan_stale");
            Bytes entrance;append_le(entrance,0x4013,2);append_le(entrance,init.game_server_id,2);
            append_le(entrance,static_cast<std::uint16_t>(landing.position),2);
            if(portal->confirmation!=entrance || portal->expects_client_request())
                throw CodecError("richonline_boss_portal_confirmation_invalid");
            if(portal->continuation==RichonlinePortalContinuation::random_teleport) {
                if(cell.static_type!=58 || portal->random_destinations.empty())
                    throw CodecError("richonline_random_teleport_plan_invalid");
                const auto chosen=rules.random(portal->random_destinations.size());
                if(chosen>=portal->random_destinations.size())
                    throw CodecError("richonline_random_teleport_rng_invalid");
                const auto destination=portal->random_destinations[chosen];
                if(destination==landing.position || !topology.cell(destination).walkable)
                    throw CodecError("richonline_random_teleport_destination_invalid");
                std::vector<Bytes> messages;
                if(!landing.sent_stop) messages.push_back(std::move(entrance));
                Bytes relocation;append_le(relocation,0x4209,2);append_le(relocation,init.game_server_id,2);
                append_le(relocation,static_cast<std::uint16_t>(destination),2);
                messages.push_back(std::move(relocation));
                if(rules.log) rules.log("richonline_random_teleport actor="+std::to_string(actor)+
                    " source="+std::to_string(landing.position)+" destination="+std::to_string(destination)+
                    " policy=native-uniform-walkable-road-v1");
                auto& person=init.participants[actor];
                person.position=destination;person.direction=landing.heading;
                landing_counter=landing.counter;route={};checkpoint_cursor=0;authenticated_steps=0;
                return advance(std::move(messages));
            }
            if(portal->continuation==RichonlinePortalContinuation::awaiting_server_continuation) {
                const auto& exit=topology.cell(portal->authoritative_position);
                if (portal->authoritative_position==landing.position || !exit.walkable ||
                    exit.static_type!=cell.static_type ||
                    (cell.static_type==61 && topology.portal_destination(landing.position)!=portal->authoritative_position))
                    throw CodecError("richonline_boss_portal_destination_invalid");
                auto& person=init.participants[actor];
                person.position=portal->authoritative_position;person.direction=landing.heading;
                landing_counter=landing.counter;route={};checkpoint_cursor=0;authenticated_steps=0;
                return advance(landing.sent_stop ? std::vector<Bytes>{} : std::vector<Bytes>{std::move(entrance)});
            }
            if(portal->continuation!=RichonlinePortalContinuation::property_phase2 ||
                portal->authoritative_position!=landing.position)
                throw CodecError("richonline_boss_portal_continuation_invalid");
        }
        const auto context=landing_context(landing.position);
        auto card_result=!richonline_landing_controlled(status[actor]) && rules.chance_landing ? rules.chance_landing(context) : std::nullopt;
        if(!richonline_landing_controlled(status[actor]) && !card_result && rules.cards) card_result=rules.cards->land(context);
        auto result=card_result ? std::move(*card_result) : rules.landed(context);
        if(landing.sent_stop) {
            for(auto it=result.messages.begin();it!=result.messages.end();) {
                if(it->size()>=2 && read_le(View(*it).first(2))==0x4013) {
                    if(it->size()!=6 || read_le(View(*it).subspan(2,2))!=init.game_server_id ||
                        read_le(View(*it).subspan(4,2))!=static_cast<std::uint16_t>(landing.position))
                        throw CodecError("richonline_boss_npc_followup_stop_mismatch");
                    it=result.messages.erase(it);
                } else ++it;
            }
        }
        auto& person=init.participants[actor];
        person.position=landing.position;person.direction=landing.heading;
        landing_counter=landing.counter;route={};
        return resolve(std::move(result));
    }
    std::vector<Bytes> npc_result(RichonlineNpcSessionResult result) {
        if(result.sent_stop4013 && npc_landing) npc_landing->sent_stop=true;
        if(result.wait==RichonlineNpcWait::roulette34) {
            npc_pending_counter=npc_landing ? npc_landing->counter : active_counter;
            npc_retired_counter.reset();npc_deadline=rules.now()+rules.npc_roulette_timeout;
            phase=Phase::npc;return std::move(result.messages);
        }
        if(npc_pending_counter) {npc_retired_counter=npc_pending_counter;npc_pending_counter.reset();}
        npc_deadline.reset();
        if(result.wait==RichonlineNpcWait::settlement) {
            if(result.bankrupt_actor && rules.terminal)
                return terminal(std::move(result.messages),{*result.bankrupt_actor},RichonlineTerminalReason::npc_money);
            phase=Phase::npc;return std::move(result.messages);
        }
        switch(result.continuation) {
        case RichonlineNpcContinuation::landing_phase1: {
            if(!npc_landing) throw CodecError("richonline_boss_npc_landing_missing");
            const auto landing=*npc_landing;npc_landing.reset();
            auto following=finish_landing(landing);
            result.messages.insert(result.messages.end(),std::make_move_iterator(following.begin()),
                std::make_move_iterator(following.end()));
            return std::move(result.messages);
        }
        case RichonlineNpcContinuation::restore_action:
            if(npc_landing) throw CodecError("richonline_boss_npc_restore_during_landing");
            await_roll();return std::move(result.messages);
        case RichonlineNpcContinuation::landing_phase6:
            if(npc_landing) throw CodecError("richonline_boss_npc_temple_during_ground_landing");
            return resolve({std::move(result.messages),RichonlineLandingProgress::complete});
        }
        throw CodecError("richonline_boss_npc_continuation_invalid");
    }
    std::vector<Bytes> ground_landing(PendingLanding landing,std::vector<Bytes> messages={}) {
        consume_ice_landing(landing.position);
        if(has_fire(landing.position)) {
            if(!landing.sent_stop) {
                Bytes stop;append_le(stop,0x4013,2);append_le(stop,init.game_server_id,2);
                append_le(stop,static_cast<std::uint16_t>(landing.position),2);
                messages.push_back(std::move(stop));landing.sent_stop=true;
            }
            auto refs=combat_refs(landing.position);
            auto effect=rules.combat->fire_landing(refs,actor,landing.position,rules.fire_traps->npc26_damage,
                [&]{auto context=landing_context(landing.position);context.actor_status=status[actor];rules.npc_landing_preflight(context);});
            if(!effect.bankrupt_actors.empty())
                return terminal(std::move(messages),std::move(effect.bankrupt_actors),RichonlineTerminalReason::fire_trap);
        }
        if(rules.combat && rules.combat->has_mine(landing.position)) {
            auto refs=combat_refs(landing.position);
            auto explosion=rules.combat->stepped_mine(refs,landing.position);
            if(!landing.sent_stop) {
                Bytes stop;append_le(stop,0x4013,2);append_le(stop,init.game_server_id,2);
                append_le(stop,static_cast<std::uint16_t>(landing.position),2);
                messages.push_back(std::move(stop));landing.sent_stop=true;
            }
            messages.insert(messages.end(),std::make_move_iterator(explosion.packets.begin()),
                std::make_move_iterator(explosion.packets.end()));
            if(!explosion.bankrupt_actors.empty())
                return terminal(std::move(messages),std::move(explosion.bankrupt_actors),RichonlineTerminalReason::stepped_mine);
        }
        if(rules.npcs) {
            auto event=rules.npcs->landing(landing_context(landing.position),landing.counter,status[actor],
                rules.npc_landing_preflight);
            if(event) {
                // A timed explosion or stepped mine already supplied this stop.
                if(landing.sent_stop && event->sent_stop4013) {
                    std::erase_if(event->messages,[&](const Bytes& packet) {
                        if(packet.size()<2 || read_le(View(packet).first(2))!=0x4013) return false;
                        if(packet.size()!=6 || read_le(View(packet).subspan(2,2))!=init.game_server_id ||
                            read_le(View(packet).subspan(4,2))!=static_cast<std::uint16_t>(landing.position))
                            throw CodecError("richonline_boss_npc_followup_stop_mismatch");
                        return true;
                    });
                }
                npc_landing=landing;auto following=npc_result(std::move(*event));
                messages.insert(messages.end(),std::make_move_iterator(following.begin()),
                    std::make_move_iterator(following.end()));return messages;
            }
        }
        auto following=finish_landing(landing);
        messages.insert(messages.end(),std::make_move_iterator(following.begin()),
            std::make_move_iterator(following.end()));return messages;
    }
    bool has_fire(std::int16_t position) const {
        if(!rules.fire_traps) return false;
        const auto ground=rules.ground->snapshot();const auto found=ground.objects.find(position);
        return found!=ground.objects.end() && found->second.npc==26;
    }
    RichonlineHibernateSnapshot hibernate_snapshot() const {
        if(!rules.hibernate || !rules.cards) throw CodecError("richonline_boss_hibernate_capability_required");
        RichonlineHibernateSnapshot snapshot{};
        snapshot.game_id=init.game_server_id;snapshot.calendar=active_counter;
        snapshot.active_actor=static_cast<std::int8_t>(actor);snapshot.roll_phase=phase==Phase::roll;
        snapshot.active_actor_can_act=active[actor] && !controlled_roll_actor() && !status[actor].frozen;
        for(std::uint8_t slot=0;slot<status.size();++slot) {
            auto& target=snapshot.actors[slot];
            target.present=active[slot];target.status=status[slot];target.relations1472=relations1472[slot];
            target.inventory.actor=slot;target.inventory.owner_actor=slot;
            if(slot==init.local_slot) target.inventory.main=rules.cards->inventory();
            // This two-actor owner validates a synthetic BOSS at slot1. It has
            // no opening/reward inventory or profile equipment; never borrow
            // the human's inventory when resolving its automatic protection.
            target.inventory.equipment_search_enabled=false;
            if(!target.present) continue;
            const auto raw=rules.hibernate->raw_actor(slot);
            if(!raw.hotel1493 || !raw.hospital1494 || !raw.jail1495 || !raw.kidnapped1497)
                throw CodecError("richonline_boss_hibernate_raw_actor_unknown");
            target.raw1493=*raw.hotel1493;target.raw1494=*raw.hospital1494;
            target.raw1495=*raw.jail1495;target.raw1497=*raw.kidnapped1497;
        }
        return snapshot;
    }
    std::vector<Bytes> hibernate(View plain) {
        auto plan=prepare_card(164,[&] {
            const auto request=decode_richonline_hibernate164(plain);require_local_controls();
            if(phase!=Phase::roll || actor!=init.local_slot) throw CodecError("richonline_boss_hibernate_out_of_phase");
            const auto before=hibernate_snapshot();
            return plan_richonline_hibernate(request,init.game_server_id,static_cast<std::int8_t>(actor),
                rules.cards->map_name(),*rules.hibernate->resources,rules.hibernate->rules,before);
        });
        if(!plan) return {encode_richonline_dice_recovery400b(init.game_server_id)};
        auto& prepared=*plan;const auto& before=prepared.before;
        std::array<std::optional<RichonlineNpcSession::PreparedStatusChange>,2> clocks;
        for(std::uint8_t slot=0;slot<status.size();++slot)
            if(rules.npcs && before.actors[slot].status!=prepared.after.actors[slot].status)
                clocks[slot]=rules.npcs->prepare_status_change(slot,status[slot],prepared.after.actors[slot].status);
        std::vector<Bytes> messages{std::move(prepared.response40f4)};
        AcceptedHibernate accepted{};std::copy(plain.begin(),plain.end(),accepted.request.begin());accepted.turn=turn_sequence;
        if(hibernate_snapshot()!=before) throw CodecError("richonline_boss_hibernate_snapshot_changed");
        for(std::uint8_t slot=0;slot<status.size();++slot)
            if(clocks[slot] && !rules.npcs->matches_status_change(*clocks[slot],status[slot]))
                throw CodecError("richonline_boss_hibernate_clock_changed");
        // All allocations and authority callbacks finish before this serialized
        // commit. The synthetic actor's empty inventory is part of the owner contract.
        for(std::uint8_t slot=0;slot<status.size();++slot) {
            if(clocks[slot]) static_cast<void>(rules.npcs->commit_status_change(*clocks[slot],status[slot]));
            else status[slot]=prepared.after.actors[slot].status;
            relations1472[slot]=prepared.after.actors[slot].relations1472;
        }
        rules.cards->commit_inventory(prepared.after.actors[init.local_slot].inventory.main);
        accepted_hibernate=accepted;
        return messages;
    }
    bool raw_available(std::uint8_t slot) const {
        if(!rules.raw_authority) return false;
        const auto& raw=rules.raw_authority->actor(slot);
        return raw.hotel1493 && raw.hospital1494 && raw.jail1495 && raw.kidnapped1497 &&
            *raw.hotel1493==-1 && *raw.hospital1494==-1 && *raw.jail1495==-1 && *raw.kidnapped1497==-1;
    }
    std::vector<Bytes> refuse_card(std::uint32_t opcode,const std::string& reason) const {
        if(rules.log) rules.log("richonline_card_refused opcode="+std::to_string(opcode)+" reason="+reason);
        return {encode_richonline_dice_recovery400b(init.game_server_id)};
    }
    template<class Planner>
    auto prepare_card(std::uint32_t opcode,Planner&& planner) const -> std::optional<std::invoke_result_t<Planner>> {
        try { return planner(); }
        catch(const CodecError& error) {
            if(rules.log) rules.log("richonline_card_refused opcode="+std::to_string(opcode)+" reason="+error.what());
            return {};
        }
    }
    std::vector<Bytes> auxiliary_card(View plain,std::uint32_t opcode) {
        std::optional<RichonlineBossCards::PreparedConsumption> consumption;
        std::optional<RichonlineGroundObjects::Prepared> ground;
        std::optional<RichonlineNpcSession::PreparedStatusChange> clock;
        std::vector<RichonlineGameFundsUpdate> funds;
        std::vector<Bytes> messages;
        auto after_status=status;
        auto after_relations=relations1472;
        auto after_participants=init.participants;
        RichonlineChanceInventory inventory{};
        std::uint8_t target=actor;
        bool enter_jail=false;
        try {
            require_local_controls();
            const auto size=opcode==122 || opcode==142 || opcode==161 || opcode==162 ? 6U : 8U;
            if(phase!=Phase::roll || actor!=init.local_slot || !rules.cards || !active[actor] ||
                plain.size()!=size || read_le(plain.subspan(2,2))!=active_counter || plain[4]>=8 || plain[5]!=0)
                throw CodecError("richonline_auxiliary_card_request_invalid");
            const auto card=opcode==161 ? 503 : opcode==162 ? 504 : opcode==116 ? 1053 :
                opcode==117 ? 1054 : opcode==121 ? 1060 : opcode==122 ? 1061 : opcode==132 ? 1072 :
                opcode==135 ? 1078 : opcode==142 ? 1115 : opcode==143 ? 1116 : 1130;
            consumption=rules.cards->prepare_consumption(static_cast<std::int8_t>(plain[4]),static_cast<std::int16_t>(card));
            if(!consumption) throw CodecError("richonline_auxiliary_card_not_owned");
            inventory=consumption->remaining_inventory;
            Bytes response;append_le(response,opcode+0x4050U,2);append_le(response,init.game_server_id,2);
            response.insert(response.end(),plain.begin()+4,plain.end());
            if(opcode==116 || opcode==117 || opcode==121 || opcode==132 || opcode==135 || opcode==167) {
                target=plain[6];
                if(target>=active.size() || !active[target]) throw CodecError("richonline_auxiliary_card_target_invalid");
                if(opcode!=116) response[7]=0;
            }
            switch(opcode) {
            case 116:
                if(target==actor || plain[7]>=8) throw CodecError("richonline_theft_card_target_invalid");
                // The synthetic BOSS has no inventory. Its UI hand is not an
                // authority for borrowing cards from the local player's hand.
                throw CodecError("richonline_theft_victim_inventory_empty");
            case 117:
                if(target==actor || !raw_available(target) || status[target].frozen || !topology.jail_positions())
                    throw CodecError("richonline_frame_target_unavailable");
                if(!status[target].protected_from_status) {
                    after_participants[target].position=(*topology.jail_positions())[0];
                    after_status[target].stay=0; // NEW7F8160 clears1496.
                    enter_jail=true;
                }
                if(static_cast<std::int8_t>(after_relations[actor][target])>0)
                    after_relations[actor][target]=after_relations[target][actor]=0;
                break;
            case 121:
                if(target==actor) throw CodecError("richonline_alliance_target_self");
                after_relations[actor][target]=after_relations[target][actor]=rules.alliance_days;
                break;
            case 122: {
                if(!rules.ground) throw CodecError("richonline_open_road_authority_required");
                const auto route_plan=build_richonline_route(topology,
                    {init.participants[actor].position,init.participants[actor].direction,10,{},false,true},rules.random);
                const auto before=rules.ground->snapshot();auto after=before.objects;
                // Animation20 removes only the ten destination cells; it neither
                // relocates the actor nor clears the starting cell.
                for(const auto position:route_plan.landings) after.erase(position);
                ground=rules.ground->prepare(before,after);
                response.resize(9,0);
                for(std::size_t i=0;i<route_plan.directions.size();++i)
                    response[6+i/4]|=static_cast<std::uint8_t>(route_plan.directions[i]<<(2*(i%4)));
                break;
            }
            case 132: // 40D4 opens a local inspection dialog; no C2S acknowledgement.
            case 167: // Animation44 is visual only.
                break;
            case 135:
                richonline_detach_possession(after_status[target]);
                after_status[target].timed_bomb.reset();after_status[target].timed_bomb_owner.reset();
                after_status[target].sleepwalking=0;after_status[target].turtle=0;
                after_status[target].stay=0;after_status[target].one_step=0;after_status[target].six_steps=0;
                after_status[target].frozen=0; //1500; rage immunity1696 is preserved.
                for(std::uint8_t other=0;other<active.size();++other)
                    after_relations[target][other]=after_relations[other][target]=0;
                break;
            case 142:
                for(auto& slot:inventory)
                    if(slot.card_id==1044 || slot.card_id==1045 || slot.card_id==1046 || slot.card_id==1063 || slot.card_id==1075)
                        slot={};
                break;
            case 143: {
                const auto position=static_cast<std::int16_t>(read_le(plain.subspan(6,2)));
                if(position<0 || static_cast<std::size_t>(position)>=topology.cells().size() || !topology.cell(position).walkable)
                    throw CodecError("richonline_teleport_card_target_invalid");
                after_participants[actor].position=position;
                break;
            }
            case 161: {
                std::vector<std::uint8_t> eligible;
                for(std::uint8_t slot=0;slot<active.size();++slot)
                    if(active[slot] && raw_available(slot) && !status[slot].frozen)
                        eligible.push_back(slot);
                if(eligible.size()<2) throw CodecError("richonline_swap_card_participants_insufficient");
                for(std::size_t i=0;i<eligible.size();++i)
                    after_participants[eligible[i]].position=init.participants[eligible[(i+1)%eligible.size()]].position;
                break;
            }
            case 162: {
                if(!rules.ledger) throw CodecError("richonline_lottery_ledger_required");
                // Explicit simulator policy, not an inferred original jackpot table.
                constexpr std::uint32_t award=15000;
                const auto before=rules.ledger->snapshot(actor);auto after=before.funds;
                if(after.cash>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())-award)
                    throw CodecError("richonline_lottery_cash_overflow");
                after.cash+=award;funds.push_back({actor,before,after});
                response.resize(8,0);append_le(response,award,4);
                break;
            }
            default: throw CodecError("richonline_auxiliary_card_kind_invalid");
            }
            if(rules.npcs && after_status[target]!=status[target])
                clock=rules.npcs->prepare_status_change(target,status[target],after_status[target]);
            messages.push_back(std::move(response));
        } catch(const CodecError& error) { return refuse_card(opcode,error.what()); }
        const auto commit=[&]() {
            if(rules.cards->inventory()!=consumption->source_inventory ||
                (ground && !rules.ground->matches(*ground)) ||
                (clock && !rules.npcs->matches_status_change(*clock,status[target]))) return false;
            if(ground && !rules.ground->commit_prepared(*ground)) std::terminate();
            if(clock && !rules.npcs->commit_status_change(*clock,status[target])) std::terminate();
            if(enter_jail) rules.raw_authority->enter_jail(target,static_cast<std::int8_t>(rules.jail_days));
            status=after_status;relations1472=after_relations;
            init.participants=std::move(after_participants);rules.cards->commit_inventory(inventory);
            return true;
        };
        if(funds.empty() ? !commit() : !rules.ledger->commit_batch(funds,commit))
            throw CodecError("richonline_auxiliary_card_stale");
        return messages;
    }
    std::vector<Bytes> action(View plain) {
        if(phase==Phase::finished && plain.size()>=2 && read_le(plain.first(2))==0x12 && retired(plain)) return {};
        if (phase == Phase::closed || phase == Phase::finished) throw CodecError("richonline_boss_session_closed");
        if (plain.size() < 2) throw CodecError("richonline_boss_action_truncated");
        if (phase==Phase::junction && retired(plain)) return {};
        const auto opcode = read_le(plain.first(2));
        if(opcode==21 && retired_jail_exit && plain.size()==4 &&
            read_le(plain.subspan(2,2))==retired_jail_exit->counter) return {};
        if(opcode==164 && retired(plain)) return {};
        if(opcode==0x12 && retired(plain)) return {};
        if (opcode==0x27 && phase!=Phase::bank && retired(plain)) return {};
        if (opcode==22 && phase!=Phase::roll && retired(plain)) return {};
        if (opcode==0x10 && retired(plain)) return {};
        if(opcode==34 && phase!=Phase::npc && retired(plain)) return {};
        if((opcode==0x38 || opcode==0x39) &&
            (!pending_decision || pending_decision->opcode!=opcode) && retired(plain)) return {};
        try {
        switch (opcode) {
        case 21:
            if(phase!=Phase::jail_exit || actor!=init.local_slot || plain.size()!=4 ||
                read_le(plain.subspan(2,2))!=active_counter) throw CodecError("richonline_jail_exit_ack_invalid");
            return finish_jail_exit();
        case 116: case 117: case 121: case 122: case 132: case 135:
        case 142: case 143: case 161: case 162: case 167:
            return auxiliary_card(plain,opcode);
        case 152: {
            const auto plan=prepare_card(opcode,[&] {
                require_local_controls();
                if(phase!=Phase::roll || actor!=init.local_slot || !active[actor] || !rules.cards ||
                    plain.size()!=6 || read_le(plain.subspan(2,2))!=active_counter || plain[4]>=8 || plain[5]!=0)
                    throw CodecError("richonline_shuffle_card_request_invalid");
                return rules.cards->prepare_shuffle(static_cast<std::int8_t>(plain[4]),actor,rules.random);
            });
            if(!plan) return {encode_richonline_dice_recovery400b(init.game_server_id)};
            std::vector<Bytes> response{plan->confirmation40e8};
            if(rules.cards->inventory()!=plan->source_inventory)
                throw CodecError("richonline_shuffle_card_stale");
            rules.cards->commit_inventory(plan->remaining_inventory);
            return response;
        }
        case 159: {
            if(phase!=Phase::roll || actor!=init.local_slot || plain.size()!=8 ||
                read_le(plain.subspan(2,2))!=active_counter || plain[4]>=8 || plain[5]!=0 ||
                !rules.combat || controlled_roll_actor()) return refuse_card(opcode,"detonation_request_invalid");
            // Sender651050 leaves+6/+7 uninitialized; never treat them as a target.
            auto refs=combat_refs();auto result=rules.combat->detonate_card(refs,plain[4],rules.log);
            if(!result.bankrupt_actors.empty()) {
                if(!result.packets.empty()) result.packets.pop_back(); // No controls after a fatal blast.
                return terminal(std::move(result.packets),std::move(result.bankrupt_actors),RichonlineTerminalReason::human_attack);
            }
            return std::move(result.packets);
        }
        case 99: case 100: case 119:
        case 125: case 126: case 127: case 128: case 129:
        case 146: case 147: case 148: case 149: case 150: case 151:
            // These property/stock effects still need authoritative
            // state. Restore controls without spending an unimplemented card.
            return refuse_card(opcode,"card_effect_unimplemented");
        case 0x14: {
            const auto request=std::get<RichonlineDiceChoice14>(parse_richonline_movement_request(plain));
            // NEW70A7E0 can select a cheaper count while refreshing balance
            // controls. This changes only the local player's next preference.
            if(phase==Phase::loading)
                throw CodecError("richonline_boss_dice_choice_out_of_phase");
            if(request.calendar_counter!=active_counter)
                throw CodecError("richonline_boss_dice_choice_counter_mismatch");
            human_dice_count=request.count;
            return {};
        }
        case 164: return hibernate(plain);
        case 110: {
            const auto prepared=prepare_card(opcode,[&] {
                const auto request=decode_richonline_timed_bomb110(plain);require_local_controls();
                if(phase!=Phase::roll || actor!=init.local_slot || !rules.timed_bombs || !rules.combat)
                    throw CodecError("richonline_boss_timed_bomb_card_out_of_phase");
                return std::pair{request,timed_context(init.participants[actor].position)};
            });
            if(!prepared) return {encode_richonline_dice_recovery400b(init.game_server_id)};
            const auto& [request,context]=*prepared;auto refs=combat_refs();
            auto result=rules.combat->timed_bomb_card(refs,actor,request,active_counter,
                *rules.timed_bombs->resources,context.raw,rules.timed_bombs->response_opaque7,rules.log);
            return std::move(result.packets);
        }
        case 109: case 111: case 124: case 133: {
            const auto request=parse_richonline_target_card(plain);
            if(phase!=Phase::roll || actor!=init.local_slot || !rules.combat)
                throw CodecError("richonline_boss_attack_card_out_of_phase");
            auto refs=combat_refs();auto result=rules.combat->human_card(refs,request,active_counter,true,rules.log);
            if(!result.bankrupt_actors.empty())
                return terminal(std::move(result.packets),std::move(result.bankrupt_actors),RichonlineTerminalReason::human_attack);
            return std::move(result.packets);
        }
        case 112: case 113: {
            const auto request=parse_richonline_deity_card(plain);
            require_local_controls();
            if(phase!=Phase::roll || actor!=init.local_slot || !rules.npcs)
                throw CodecError("richonline_boss_deity_card_out_of_phase");
            const auto target=static_cast<std::uint8_t>(request.target_actor);
            if(target>=init.participants.size()) throw CodecError("richonline_deity_card_target_invalid");
            const auto source=landing_context(init.participants[actor].position);
            std::vector<std::int16_t> candidates;
            if(request.kind==RichonlineDeityCard::summon1047) {
                if(!rules.npc_summon_candidates) throw CodecError("richonline_boss_summon_policy_required");
                candidates=rules.npc_summon_candidates(source);
                for(const auto position:candidates)
                    if(!topology.cell(position).walkable) throw CodecError("richonline_boss_summon_candidate_cell_invalid");
            }
            return npc_result(rules.npcs->deity_card(plain,source,active_counter,status[target],raw_available(target),candidates,rules.random));
        }
        case 34:
            if(phase!=Phase::npc || !rules.npcs || !rules.npcs->awaiting_roulette())
                throw CodecError("richonline_boss_npc_roulette_out_of_phase");
            return npc_result(rules.npcs->handle(plain,actor,status[actor]));
        case 131: {
            const auto request=decode_richonline_fortune_card(plain);
            require_local_controls();
            if(phase!=Phase::roll || actor!=init.local_slot || !rules.npcs)
                throw CodecError("richonline_boss_fortune_card_out_of_phase");
            if(request.calendar!=active_counter) throw CodecError("richonline_boss_fortune_card_counter_mismatch");
            return npc_result(rules.npcs->fortune_card(plain,landing_context(init.participants[actor].position),status[actor]));
        }
        case 130: {
            const auto request=decode_richonline_wealth_card(plain);
            require_local_controls();
            if(phase!=Phase::roll || actor!=init.local_slot || !rules.npcs)
                throw CodecError("richonline_boss_wealth_card_out_of_phase");
            if(request.calendar!=active_counter) throw CodecError("richonline_boss_wealth_card_counter_mismatch");
            return npc_result(rules.npcs->wealth_card(plain,landing_context(init.participants[actor].position),status[actor]));
        }
        case 144: case 145: case 154: case 168: {
            auto plan=prepare_card(opcode,[&] {
                const auto request=parse_richonline_cosmetic_card(plain);
                require_local_controls();
                if(phase!=Phase::roll || actor!=init.local_slot || !rules.cards)
                    throw CodecError("richonline_boss_cosmetic_card_out_of_phase");
                return plan_richonline_cosmetic_card(init.game_server_id,request,active_counter,*rules.cards);
            });
            if(!plan) return {encode_richonline_dice_recovery400b(init.game_server_id)};
            auto& prepared=*plan;
            std::vector<Bytes> messages{std::move(prepared.response)};
            rules.cards->commit_consumption(prepared.consumption);
            return messages;
        }
        case 104: case 105: case 106: case 107: case 136: case 141: {
            struct Planned {
                RichonlineMotionCardPlan card;
                RichonlineChanceInventory inventory;
                std::uint8_t target;
                std::optional<RichonlineNpcSession::PreparedStatusChange> clock;
                std::optional<PreparedMove> movement;
            };
            auto plan=prepare_card(opcode,[&] {
                const auto request=parse_richonline_motion_card(plain);
                require_local_controls();
                if(phase!=Phase::roll || actor!=init.local_slot || !rules.motion_cards || !rules.cards)
                    throw CodecError("richonline_boss_motion_card_out_of_phase");
                const auto target=static_cast<std::uint8_t>(request.target_actor);
                if(target>=init.participants.size()) throw CodecError("richonline_motion_card_target_invalid");
                const auto& person=init.participants[target];
                const RichonlineMotionCardTarget before{request.target_actor,person.position,person.direction,
                    status[target],active[target],raw_available(target)};
                auto card=plan_richonline_motion_card(init.game_server_id,request,active_counter,
                    static_cast<std::int8_t>(actor),before,*rules.motion_cards,topology,rules.random,*rules.cards);
                auto inventory=card.consumption.remaining_inventory;
                if(opcode==107) {
                    if(!rules.hibernate) throw CodecError("richonline_sleep_protection_resources_required");
                    RichonlineProtectionInventory protection_inventory{target,target,{},std::nullopt,false};
                    if(target==init.local_slot) protection_inventory.main=inventory;
                    const auto protection=resolve_richonline_sleep_protection(rules.cards->map_name(),
                        *rules.hibernate->resources,protection_inventory,status[target]);
                    if(protection.consumed || status[target].protected_from_status) card.after.status=status[target];
                    if(target==init.local_slot) inventory=protection.after.main;
                }
                auto clock=rules.npcs ? std::optional{rules.npcs->prepare_status_change(target,
                    status[target],card.after.status)} : std::nullopt;
                auto movement=card.movement_steps ? std::optional{prepare_move(*card.movement_steps)} : std::nullopt;
                return Planned{std::move(card),inventory,target,std::move(clock),std::move(movement)};
            });
            if(!plan) return {encode_richonline_dice_recovery400b(init.game_server_id)};
            auto& prepared=plan->card;auto& inventory=plan->inventory;const auto target=plan->target;
            auto& clock_change=plan->clock;auto& movement=plan->movement;
            std::vector<Bytes> messages{std::move(prepared.response)};
            if (prepared.recovery) messages.push_back(std::move(*prepared.recovery));
            if(movement) movement->messages.insert(movement->messages.begin(),std::move(messages.front()));
            if(rules.cards->inventory()!=prepared.consumption.source_inventory ||
                (clock_change && !rules.npcs->matches_status_change(*clock_change,status[target])))
                throw CodecError("richonline_boss_motion_card_stale");
            rules.cards->commit_inventory(inventory);
            if(clock_change) {
                if(!rules.npcs->commit_status_change(*clock_change,status[target]))
                    throw CodecError("richonline_boss_motion_npc_status_changed");
            } else status[target]=prepared.after.status;
            init.participants[target].direction=prepared.after.heading;
            if(opcode==107) {
                if(static_cast<std::int8_t>(relations1472[actor][target])>0)
                    relations1472[actor][target]=relations1472[target][actor]=0;
                if(target==actor) await_roll();
            }
            if(movement) return commit_move(std::move(*movement));
            if (prepared.continuation==RichonlineMotionCardContinuation::await_same_position17) {
                route={}; checkpoint_cursor=0; phase=Phase::stationary;
            }
            return messages;
        }
        case 0x27:
            if (phase!=Phase::bank) throw CodecError("richonline_boss_bank_out_of_phase");
            return bank_result(rules.bank->handle(plain));
        case 0x28: {
            const auto request=decode_richonline_game_bank_pass(plain);
            if (phase!=Phase::moving) throw CodecError("richonline_boss_bank_pass_out_of_phase");
            const auto checkpoint=next_bank_checkpoint();
            if (!checkpoint || route.landings[*checkpoint]!=request.position)
                throw CodecError("richonline_boss_bank_checkpoint_mismatch");
            if(rules.ground && request.calendar_counter!=active_counter)
                throw CodecError("richonline_boss_movement_counter_mismatch");
            auto progress=prepare_timed_progress(0x28,request.calendar_counter,request.position);
            auto ground_progress=!progress ? prepare_ground_progress(*checkpoint) : std::nullopt;
            if(progress) static_cast<void>(commit_timed_progress(*progress));
            else if(ground_progress) commit_ground_progress(*ground_progress,*checkpoint);
            return open_bank(request.position,request.calendar_counter,RichonlineGameBankVisit::passing,checkpoint);
        }
        case 50: {
            const auto request=parse_richonline_card_discard50(plain);
            require_local_controls();
            if (phase!=Phase::roll || actor!=init.local_slot) throw CodecError("richonline_boss_discard_out_of_phase");
            if (!rules.cards) throw CodecError("richonline_boss_card_inventory_missing");
            auto prepared=rules.cards->prepare_discard(request,static_cast<std::int8_t>(actor));
            rules.cards->commit_inventory(prepared.remaining_inventory);
            return {std::move(prepared.confirmation4033)};
        }
        case 0x34:
            if (phase!=Phase::junction || actor!=init.local_slot) throw CodecError("richonline_junction_out_of_phase");
            return finish_junction(junction->decide(plain,rules.now()));
        case 0x10: {
            const auto request = std::get<RichonlineMoveRequest10>(parse_richonline_movement_request(plain));
            if (phase != Phase::roll || actor != init.local_slot) throw CodecError("richonline_boss_roll_out_of_phase");
            if (request.calendar_counter!=active_counter) throw CodecError("richonline_boss_roll_counter_mismatch");
            if (request.parameter != 0) throw CodecError("richonline_boss_roll_parameter_unsupported");
            return controlled_roll_actor() ? controlled_move() : random_move();
        }
        case 108: case 158: case 165: {
            std::optional<RichonlineGroundCardPlan> planned;
            try {
                const auto request=opcode==108 ? decode_richonline_roadblock108(plain) : opcode==158 ?
                    decode_richonline_supermine158(plain) : decode_richonline_ground_card165(plain);
                require_local_controls();
                if(!rules.cards || !rules.ground || !rules.ground_card_visible)
                    throw CodecError("richonline_boss_ground_card_authority_required");
                const auto valid=request.position>=0 && static_cast<std::size_t>(request.position)<topology.cells().size();
                const auto* cell=valid ? &topology.cell(request.position) : nullptr;
                const auto occupied=std::any_of(init.participants.begin(),init.participants.end(),
                    [&](const auto& participant){return participant.position==request.position;});
                const RichonlineGroundCardTurnContext context{init.game_server_id,active_counter,
                    static_cast<std::int8_t>(actor),static_cast<std::int8_t>(init.local_slot),phase==Phase::roll,
                    !controlled_roll_actor() && !status[actor].frozen && active[actor],valid,cell && cell->walkable,
                    valid && rules.ground_card_visible(actor,init.participants[actor].position,request.position),occupied,
                    cell ? cell->static_type : static_cast<std::int8_t>(-1)};
                planned=plan_richonline_banana_card(request,context,rules.cards->inventory(),rules.ground->snapshot());
            } catch(const CodecError& error) {
                if(rules.log) rules.log(std::string("richonline_ground_card_refused reason=")+error.what());
                return {encode_richonline_dice_recovery400b(init.game_server_id)};
            }
            auto ground=rules.ground->prepare(planned->expected_ground,planned->after_ground);
            std::vector<Bytes> response{std::move(planned->response40f5)};
            if(rules.cards->inventory()!=planned->expected_inventory || !rules.ground->matches(ground))
                throw CodecError("richonline_boss_ground_card_stale");
            if(!rules.ground->commit_prepared(ground)) std::terminate();
            rules.cards->commit_inventory(planned->after_inventory);
            return response;
        }
        case 96: case 97: case 98: case 120: case 134: case 163:
        case 101: case 102: case 114: case 115: case 123: case 166:
        case 169: case 170: case 171: case 172: case 173: case 174: {
            std::optional<RichonlineBossCards::PreparedConsumption> consumption;
            std::optional<RichonlineBossProperty::PreparedCombat> building;
            std::vector<RichonlineGameFundsUpdate> updates;
            std::vector<Bytes> response;
            std::uint8_t target=0;
            try {
                require_local_controls();
                if(phase!=Phase::roll || actor!=init.local_slot || !rules.cards ||
                    plain.size()!=((opcode==96 || opcode==102 || opcode==120 || opcode==134 || opcode==163 || opcode==166) ? 6U : 8U) ||
                    read_le(plain.subspan(2,2))!=active_counter || plain[4]>=8 || plain[5]!=0)
                    throw CodecError("richonline_normal_card_request_invalid");
                const bool conversion=opcode>=169 && opcode<=174;
                // NEW 40FD is pyramid (514/16); 40FE is garden (513/15).
                constexpr std::array<std::int8_t,6> conversion_kinds{11,12,13,14,16,15};
                const auto kind=conversion ? conversion_kinds.at(opcode-169) : std::int8_t{-1};
                const auto card_id=conversion ? 498+kind : opcode==163 ? 505 : opcode==166 ? 508 :
                    opcode==96 || opcode==97 || opcode==98 ? static_cast<int>(opcode)+935 : opcode==120 ? 1059 : opcode==134 ? 1077 :
                    opcode==101 ? 1036 : opcode==102 ? 1037 : opcode==114 ? 1051 : opcode==115 ? 1052 : 1062;
                consumption=rules.cards->prepare_consumption(static_cast<std::int8_t>(plain[4]),
                    static_cast<std::int16_t>(card_id));
                if(!consumption) throw CodecError("richonline_normal_card_not_owned");
                const auto response_opcode=conversion || opcode==96 || opcode==97 || opcode==98 || opcode==120 || opcode==134 || opcode==163 ?
                    opcode+0x4050U : opcode==166 ? 0x40f6U :
                    opcode==101 ? 0x40b5U : opcode==102 ? 0x40b6U : opcode==114 ? 0x40c2U : opcode==115 ? 0x40c3U : 0x40cbU;
                Bytes packet;append_le(packet,response_opcode,2);
                append_le(packet,init.game_server_id,2);
                packet.insert(packet.end(),plain.begin()+4,plain.end());
                if(opcode==96) {
                    if(!rules.property || !rules.ledger || !rules.human_purchase_half_price)
                        throw CodecError("richonline_purchase_card_authority_required");
                    const auto ref=topology.cell(init.participants[actor].position).property_ref;
                    building=rules.property->prepare_purchase_card(ref,actor);
                    const auto price=rules.property->purchase_price(ref,actor);
                    if(!price || *price>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
                        throw CodecError("richonline_purchase_card_price_invalid");
                    const auto cost=*price;
                    const auto source=rules.ledger->snapshot(actor);
                    if(source.funds.cash<=cost)
                        throw CodecError("richonline_purchase_card_cash_insufficient");
                    auto after=source.funds;after.cash-=cost;
                    updates={{actor,source,after}};
                } else if(opcode==97 || opcode==98 || opcode==120 || opcode==134 || opcode==163) {
                    if(!rules.property) throw CodecError("richonline_property_card_authority_required");
                    const auto source=topology.cell(init.participants[actor].position).property_ref;
                    building=opcode==97 || opcode==98 ? rules.property->prepare_swap_card(source,
                        static_cast<std::int16_t>(read_le(plain.subspan(6,2))),opcode==98) :
                        rules.property->prepare_growth_card(source,opcode==163 ? std::optional{actor} : std::nullopt,
                            opcode==134 ? -1 : opcode==163 ? 2 : 1);
                } else if(opcode==101 || opcode==102) {
                    if(!rules.property) throw CodecError("richonline_destruction_card_authority_required");
                    const auto property_ref=opcode==101 ? static_cast<std::int16_t>(read_le(plain.subspan(6,2))) :
                        topology.cell(init.participants[actor].position).property_ref;
                    building=rules.property->prepare_destruction_card(property_ref,opcode==101 ? 1 : 5);
                } else if(conversion) {
                    if(!rules.property) throw CodecError("richonline_conversion_card_authority_required");
                    const auto property_ref=static_cast<std::int16_t>(read_le(plain.subspan(6,2)));
                    building=rules.property->prepare_conversion_card(property_ref,kind,actor);
                } else if(opcode==123) {
                    if(!rules.property) throw CodecError("richonline_house_card_authority_required");
                    const auto position=static_cast<std::int16_t>(read_le(plain.subspan(6,2)));
                    building=rules.property->prepare_house_card(position,actor);
                } else if(opcode==166) {
                    if(!rules.ledger) throw CodecError("richonline_equal_wealth_authority_required");
                    std::uint64_t total=0;
                    for(std::uint8_t slot=0;slot<active.size();++slot) {
                        if(!active[slot]) continue;
                        const auto source=rules.ledger->snapshot(slot);
                        total+=source.funds.cash;
                        updates.push_back({slot,source,source.funds});
                    }
                    // NEW6799C0 accumulates signed DWORD cash before division.
                    if(updates.empty() || total>static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max()))
                        throw CodecError("richonline_equal_wealth_cash_out_of_range");
                    const auto average=std::max(std::uint32_t{1},static_cast<std::uint32_t>(total/updates.size()));
                    for(auto& update:updates) update.after.cash=average;
                } else if(opcode==115) {
                    target=plain[6];packet[7]=0;
                    if(!rules.ledger || target>=active.size() || target==actor || !active[target])
                        throw CodecError("richonline_equal_poor_target_invalid");
                    const auto source=rules.ledger->snapshot(actor),victim=rules.ledger->snapshot(target);
                    const auto total=static_cast<std::uint64_t>(source.funds.cash)+victim.funds.cash;
                    // NEW670330 adds signed DWORD cash then arithmetic-shifts by
                    // one. Reject overflow rather than sending a negative balance.
                    if(total>static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max()))
                        throw CodecError("richonline_equal_poor_cash_out_of_range");
                    auto source_after=source.funds,victim_after=victim.funds;
                    source_after.cash=static_cast<std::uint32_t>(total/2);
                    victim_after.cash=source_after.cash;
                    updates={{actor,source,source_after},{target,victim,victim_after}};
                } else {
                    target=plain[6];packet[7]=0;
                    if(!rules.ledger || target>=active.size() || target==actor || !active[target])
                        throw CodecError("richonline_tax_card_target_invalid");
                    const auto source=rules.ledger->snapshot(actor),victim=rules.ledger->snapshot(target);
                    if(!source.funds.deposit || !victim.funds.deposit)
                        throw CodecError("richonline_tax_card_deposit_unknown");
                    const auto cash_tax=victim.funds.cash/10,deposit_tax=*victim.funds.deposit/10;
                    auto source_after=source.funds,victim_after=victim.funds;
                    const auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
                    if(source_after.cash>maximum-cash_tax || *source_after.deposit>maximum-deposit_tax)
                        throw CodecError("richonline_tax_card_balance_overflow");
                    source_after.cash+=cash_tax;*source_after.deposit+=deposit_tax;
                    victim_after.cash-=cash_tax;*victim_after.deposit-=deposit_tax;
                    updates={{actor,source,source_after},{target,victim,victim_after}};
                }
                response.push_back(std::move(packet));
            } catch(const CodecError& error) {
                if(rules.log) rules.log(std::string("richonline_normal_card_refused opcode=")+std::to_string(opcode)+" reason="+error.what());
                return {encode_richonline_dice_recovery400b(init.game_server_id)};
            }
            const auto commit=[&]() noexcept {
                if(rules.cards->inventory()!=consumption->source_inventory ||
                    (building && !rules.property->combat_matches(*building))) return false;
                if(building && !rules.property->commit_combat(*building)) std::terminate();
                rules.cards->commit_inventory(consumption->remaining_inventory);
                if((opcode==114 || opcode==115) && static_cast<std::int8_t>(relations1472[actor][target])>0) {
                    relations1472[actor][target]=0;relations1472[target][actor]=0;
                }
                return true;
            };
            if(!updates.empty() ? !rules.ledger->commit_batch(updates,commit) : !commit())
                throw CodecError("richonline_normal_card_stale");
            return response;
        }
        case 156: {
            if(phase!=Phase::roll || actor!=init.local_slot || plain.size()!=8 ||
                read_le(plain.subspan(2,2))!=active_counter)
                throw CodecError("richonline_boss_research_card_out_of_phase");
            RichonlineCombatBridgeResult result;
            try {
                const auto request=decode_richonline_research_card(plain);
                if(!rules.poison || !rules.combat || !rules.poison_raw_actor)
                    throw CodecError("richonline_boss_poison_authority_required");
                const RichonlineResearchCardContext context{init.game_server_id,active_counter,
                    static_cast<std::int8_t>(actor),static_cast<std::int8_t>(init.local_slot),true,
                    active[actor] && !richonline_landing_controlled(status[actor])};
                std::array<RichonlineRawActorState,8> raw{};
                for(std::uint8_t slot=0;slot<active.size();++slot) raw[slot]=rules.poison_raw_actor(slot);
                const auto footprint=richonline_poison_map_footprint(topology,init.participants[actor].position,rules.poison->range);
                auto refs=combat_refs();
                result=rules.combat->poison_card(refs,request,context,poison_use_count,*rules.poison,footprint,raw,relations1472);
            } catch(const CodecError& error) {
                if(rules.log) rules.log(std::string("richonline_poison_refused reason=")+error.what());
                return {encode_richonline_dice_recovery400b(init.game_server_id)};
            }
            if(!result.bankrupt_actors.empty())
                return terminal(std::move(result.packets),std::move(result.bankrupt_actors),RichonlineTerminalReason::poison_card);
            return std::move(result.packets);
        }
        case 155: case 157: {
            if(phase!=Phase::roll || actor!=init.local_slot || plain.size()!=8 ||
                read_le(plain.subspan(2,2))!=active_counter)
                throw CodecError("richonline_boss_research_card_out_of_phase");
            std::optional<RichonlineResearchTrapPlan> planned;
            try {
                const auto request=decode_richonline_research_card(plain);
                const auto* traps=request.card==RichonlineResearchCard::ice1181 ? rules.ice_traps.get() :
                    rules.fire_traps ? &rules.fire_traps->traps : nullptr;
                if(!traps || !rules.cards || !rules.ground || !rules.ground_card_visible)
                    throw CodecError("richonline_boss_research_card_authority_required");
                const RichonlineResearchCardContext context{init.game_server_id,active_counter,
                    static_cast<std::int8_t>(actor),static_cast<std::int8_t>(init.local_slot),true,
                    active[actor] && !richonline_landing_controlled(status[actor])};
                const auto position=*request.position;
                const bool valid=position>=0 && static_cast<std::size_t>(position)<topology.cells().size();
                const RichonlineResearchTrapMap map{static_cast<std::uint16_t>(topology.width()),
                    static_cast<std::uint16_t>(topology.height()),valid &&
                    rules.ground_card_visible(actor,init.participants[actor].position,position),
                    [this](std::int16_t target) {
                        const auto& cell=topology.cell(target);bool occupied=false;
                        for(std::size_t slot=0;slot<active.size();++slot)
                            if(active[slot] && init.participants[slot].position==target) occupied=true;
                        return RichonlineResearchTrapCell{cell.walkable,occupied,cell.static_type};
                    },static_cast<std::int8_t>(actor)};
                planned=plan_richonline_research_trap(request,context,map,*traps,
                    rules.cards->inventory(),rules.ground->snapshot());
            } catch(const CodecError& error) {
                if(rules.log) rules.log(std::string("richonline_research_card_refused reason=")+error.what());
                return {encode_richonline_dice_recovery400b(init.game_server_id)};
            }
            auto ground=rules.ground->prepare(planned->expected_ground,planned->after_ground);
            std::vector<Bytes> response{std::move(planned->success)};
            if(rules.cards->inventory()!=planned->expected_inventory || !rules.ground->matches(ground))
                throw CodecError("richonline_boss_ice_card_stale");
            if(!rules.ground->commit_prepared(ground)) std::terminate();
            rules.cards->commit_inventory(planned->after_inventory);
            return response;
        }
        case 160: {
            auto plan=prepare_card(opcode,[&] {
                const auto request=decode_richonline_clear_card160(plain);
                require_local_controls();
                if(!rules.cards || !rules.ground) throw CodecError("richonline_boss_clear_card_authority_required");
                const RichonlineClearCardContext context{init.game_server_id,active_counter,
                    static_cast<std::int8_t>(actor),static_cast<std::int8_t>(init.local_slot),phase==Phase::roll,
                    !controlled_roll_actor() && !status[actor].frozen && active[actor]};
                return plan_richonline_clear_card(request,context,rules.cards->inventory(),rules.ground->snapshot());
            });
            if(!plan) return {encode_richonline_dice_recovery400b(init.game_server_id)};
            auto& planned=*plan;
            auto ground=rules.ground->prepare(planned.expected_ground,planned.after_ground);
            std::vector<Bytes> response{std::move(planned.response40f0)};
            if(rules.cards->inventory()!=planned.expected_inventory || !rules.ground->matches(ground))
                throw CodecError("richonline_boss_clear_card_stale");
            if(!rules.ground->commit_prepared(ground)) std::terminate();
            rules.cards->commit_inventory(planned.after_inventory);
            return response;
        }
        case 103: {
            auto plan=prepare_card(opcode,[&] {
                const auto request=std::get<RichonlineCardDiceRequest103>(parse_richonline_controlled_dice_request(plain));
                require_local_controls();
                if(phase!=Phase::roll || actor!=init.local_slot || request.calendar_counter!=active_counter)
                    throw CodecError("richonline_boss_card_out_of_phase");
                const auto prepared=rules.cards ? rules.cards->prepare_use(request) : std::nullopt;
                if(!prepared) throw CodecError("richonline_controlled_dice_slot_unavailable");
                return std::pair{*prepared,prepare_move(prepared->die)};
            });
            if(!plan) return {encode_richonline_dice_recovery400b(init.game_server_id)};
            auto& [prepared,movement]=*plan;
            movement.messages.insert(movement.messages.begin(),prepared.confirmation40b7);
            rules.cards->commit_use(prepared);
            return commit_move(std::move(movement));
        }
        case 137: case 138: case 139: case 140: {
            auto plan=prepare_card(opcode,[&] {
                const auto request=parse_richonline_fixed_step_card(plain);
                require_local_controls();
                if(phase!=Phase::roll || actor!=init.local_slot || !rules.cards)
                    throw CodecError("richonline_boss_fixed_step_card_out_of_phase");
                auto card=plan_richonline_fixed_step_card(init.game_server_id,request,active_counter,*rules.cards);
                auto movement=prepare_move(card.steps);
                return std::pair{std::move(card),std::move(movement)};
            });
            if(!plan) return {encode_richonline_dice_recovery400b(init.game_server_id)};
            auto& [card,movement]=*plan;
            movement.messages.insert(movement.messages.begin(),std::move(card.confirmation));
            rules.cards->commit_consumption(card.consumption);
            return commit_move(std::move(movement));
        }
        case 22: {
            const auto request=std::get<RichonlinePaidDiceRequest22>(parse_richonline_controlled_dice_request(plain));
            require_local_controls();
            if (phase != Phase::roll || actor != init.local_slot) throw CodecError("richonline_boss_paid_dice_out_of_phase");
            if (request.calendar_counter!=active_counter) throw CodecError("richonline_boss_paid_dice_counter_mismatch");
            if (status[actor].one_step || status[actor].six_steps || status[actor].turtle || status[actor].stay)
                throw CodecError("richonline_boss_paid_dice_status_forbidden");
            std::vector<Bytes> refused{encode_richonline_dice_recovery400b(init.game_server_id)};
            if (!rules.payment) {
                if (rules.log) rules.log("richonline_boss_paid_dice_rejected reason=authenticated_payment_unavailable");
                return refused;
            }
            // The monotonic sequence disambiguates calendar low16 wrapping within
            // one match; the session nonce disambiguates matches and restarts.
            const auto operation=rules.payment_operation_prefix+":turn="+std::to_string(turn_sequence)+
                ":counter="+std::to_string(active_counter)+":paid-die:face="+std::to_string(request.selected_die);
            const auto price=rules.payment->quote_paid_die(request.selected_die,rules.payment_equipment);
            auto prepared=prepare_move(request.selected_die,price);
            const auto paid=rules.payment->paid_die(operation,request.selected_die,rules.payment_equipment);
            switch(paid.status) {
            case RichonlinePaymentStatus::committed:
                accepted_paid_move=PaidMove{request.calendar_counter,request.selected_die};
                return commit_move(std::move(prepared));
            case RichonlinePaymentStatus::duplicate:
            case RichonlinePaymentStatus::recovery_required:
                throw CodecError("richonline_boss_paid_dice_recovery_required");
            case RichonlinePaymentStatus::insufficient_reserve:
            case RichonlinePaymentStatus::account_refused:
                return refused;
            }
            throw CodecError("richonline_boss_paid_dice_result_invalid");
        }
        case 0x11: {
            const auto request = std::get<RichonlineMoveStop11>(parse_richonline_movement_request(plain));
            const auto stationary=phase==Phase::stationary;
            if (phase != Phase::moving && !stationary) throw CodecError("richonline_boss_stop_out_of_phase");
            if((rules.timed_bombs || rules.ground) && request.calendar_counter!=active_counter)
                throw CodecError("richonline_boss_movement_counter_mismatch");
            if (next_bank_checkpoint()) throw CodecError("richonline_boss_bank_checkpoint_skipped");
            const auto endpoint=stationary ? init.participants[actor].position : route.landings.back();
            const auto heading=stationary ? init.participants[actor].direction : route.directions.back();
            if (request.endpoint != endpoint) throw CodecError("richonline_boss_endpoint_mismatch");
            auto progress=!stationary ? prepare_timed_progress(0x11,request.calendar_counter,request.endpoint) : std::nullopt;
            auto ground_progress=!stationary && !progress ? prepare_ground_progress(route.landings.size()-1) : std::nullopt;
            PendingLanding landing{request.endpoint,heading,request.calendar_counter,false};
            auto context=landing_context(request.endpoint);
            if(progress) context.actor_status=progress->plan().combat.after.actors[actor]->status;
            project_ice_landing(context);
            if((rules.npcs || rules.combat || rules.ice_traps) && !has_fire(request.endpoint))
                rules.npc_landing_preflight(context);
            if(progress) static_cast<void>(commit_timed_progress(*progress));
            else if(ground_progress) commit_ground_progress(*ground_progress,route.landings.size()-1);
            return ground_landing(landing);
        }
        case 0x12: {
            const auto request=std::get<RichonlineMoveCountdown12>(parse_richonline_movement_request(plain));
            if(!rules.timed_bombs) throw CodecError("richonline_boss_intermediate_effect_unsupported");
            if(phase!=Phase::moving) throw CodecError("richonline_boss_timed_bomb_stop_out_of_phase");
            auto progress=prepare_timed_progress(0x12,request.calendar_counter,request.endpoint);
            const auto index=authenticated_steps+progress->plan().accepted_steps-1;
            PendingLanding landing{request.endpoint,route.directions[index],request.calendar_counter,true};
            const auto dies=!progress->plan().combat.bankrupt_actors.empty();
            if(!dies) {
                auto context=landing_context(request.endpoint);
                context.actor_status=progress->plan().combat.after.actors[actor]->status;
                project_ice_landing(context);
                if(!has_fire(request.endpoint)) rules.npc_landing_preflight(context);
            }
            // Reserve the retirement slot before the shared commit. It remains
            // valid across the immediately following turns and is bounded.
            retired_bomb_stops.reserve(retired_bomb_stops.size()+1);
            auto result=commit_timed_progress(*progress,request);
            retired_bomb_stops.push_back({request.calendar_counter,request.endpoint,turn_sequence});
            route={};checkpoint_cursor=0;authenticated_steps=0;
            if(!result.bankrupt_actors.empty())
                return terminal(std::move(result.packets),std::move(result.bankrupt_actors),RichonlineTerminalReason::timed_bomb);
            return ground_landing(landing,std::move(result.packets));
        }
        case 0x2a:
            // 中途效果与暂停消息不是普通落点确认，不能当成 0x11 直接结束移动。
            static_cast<void>(parse_richonline_movement_request(plain));
            throw CodecError("richonline_boss_intermediate_effect_unsupported");
        default:
            if (phase != Phase::landing) throw CodecError("richonline_boss_action_out_of_phase");
            return resolve(rules.event(plain));
        }
        } catch(const CodecError& error) {
            // These named errors arise before an NPC-card commit. Do not catch
            // inventory/ground/clock stale errors or continuation failures.
            constexpr std::array<std::string_view,18> npc_refusals{
                "richonline_deity_card_fields_invalid","richonline_deity_card_wire_invalid",
                "richonline_deity_card_calendar_mismatch","richonline_deity_card_target_invalid",
                "richonline_deity_card_ground_npc_invalid","richonline_deity_card_no_possession",
                "richonline_deity_card_not_owned","richonline_npc_session_visible_god_missing",
                "richonline_fortune_card_wire_invalid","richonline_fortune_card_inventory_invalid",
                "richonline_fortune_card_missing","richonline_wealth_card_wire_invalid",
                "richonline_wealth_card_inventory_invalid","richonline_wealth_card_missing",
                "richonline_boss_deity_card_out_of_phase","richonline_boss_fortune_card_out_of_phase",
                "richonline_boss_wealth_card_out_of_phase","richonline_npc_session_card_out_of_phase"};
            if((opcode==112 || opcode==113 || opcode==130 || opcode==131) &&
                std::ranges::find(npc_refusals,std::string_view(error.what()))!=npc_refusals.end())
                return refuse_card(opcode,error.what());
            throw;
        }
    }
};
}
RichonlineStartupPlan make_richonline_boss_turns(const RichonlineBossStartup& startup,
    RichonlineRoadTopology topology, RichonlineBossTurnRules rules) {
    if (!rules.random || !rules.landed || !rules.event || !rules.now) throw CodecError("richonline_boss_turn_rules_required");
    if((rules.npcs || rules.combat || rules.ice_traps || rules.fire_traps) && !rules.npc_landing_preflight)
        throw CodecError("richonline_boss_npc_landing_preflight_required");
    if(rules.combat && (!rules.combat_random || !rules.combat_capabilities || !rules.terminal))
        throw CodecError("richonline_boss_combat_turn_rules_required");
    if(rules.month_limit_days && !rules.terminal)
        throw CodecError("richonline_boss_month_limit_terminal_required");
    if(rules.npc_aura && (!rules.npcs || !rules.ledger || rules.ledger->actor_count()!=2 ||
        !rules.npc_aura_raw_actor || !rules.terminal || rules.npc_aura->amount<0 || rules.npc_aura->radius<0))
        throw CodecError("richonline_boss_npc_aura_capability_required");
    if(rules.timed_bombs && (!rules.combat || !rules.timed_bombs->resources || !rules.timed_bombs->step_context))
        throw CodecError("richonline_boss_timed_bomb_rules_required");
    if(rules.hibernate && (!rules.cards || !rules.hibernate->resources || !rules.hibernate->raw_actor ||
        rules.hibernate->rules.frozen_turns==0 || rules.hibernate->rules.frozen_turns>127))
        throw CodecError("richonline_boss_hibernate_rules_required");
    if(rules.npcs && (rules.npc_roulette_timeout<=std::chrono::milliseconds{0} ||
        rules.npc_roulette_timeout>std::chrono::minutes{5}))
        throw CodecError("richonline_boss_npc_roulette_timeout_invalid");
    if(rules.controlled_roll_timeout<=std::chrono::milliseconds{0} ||
        rules.controlled_roll_timeout>std::chrono::minutes{5})
        throw CodecError("richonline_boss_controlled_roll_timeout_invalid");
    if (rules.boss_dice_count<1 || rules.boss_dice_count>3)
        throw CodecError("richonline_boss_dice_count_invalid");
    if (startup.init.participants.size() != 2 || startup.init.local_slot != 0 ||
        startup.init.participants[0].lobby_identity < 0 || startup.init.participants[1].lobby_identity != -1)
        throw CodecError("richonline_boss_turn_participants_invalid");
    if (rules.route_wire.local_reserve_charge != 0) throw CodecError("richonline_boss_paid_roll_unsupported");
    if (rules.payment && (rules.payment_operation_prefix.empty() || rules.payment_operation_prefix.size()>128 ||
        rules.payment_operation_prefix.find('\0')!=std::string::npos))
        throw CodecError("richonline_boss_payment_operation_prefix_required");
    if (rules.bank) {
        if (!rules.ledger || rules.ledger->actor_count()!=startup.init.participants.size())
            throw CodecError("richonline_boss_bank_ledger_required");
        for (std::uint8_t slot=0;slot<startup.init.participants.size();++slot)
            if (!rules.ledger->snapshot(slot).funds.deposit)
                throw CodecError("richonline_boss_bank_deposit_unknown");
    }
    for (const auto& person : startup.init.participants)
        if (!topology.cell(person.position).walkable || person.direction > 3) throw CodecError("richonline_boss_turn_spawn_invalid");
    const auto mode = read_le(View(startup.room.description.record).subspan(36,4));
    if(rules.poison && (mode!=3 || !rules.combat || !rules.cards || !rules.poison_raw_actor || !rules.terminal ||
        !rules.poison->range || rules.poison->range>4 || !rules.poison->base_damage || rules.poison->base_damage>0x7fffffffU))
        throw CodecError("richonline_boss_poison_rules_required");
    if(rules.fire_traps && (mode!=3 || !rules.combat || !rules.cards || !rules.ground || !rules.ground_card_visible ||
        !rules.terminal || !rules.fire_traps->npc26_damage || rules.fire_traps->npc26_damage>0x7fffffffU ||
        !rules.fire_traps->traps.freeze_timer || rules.fire_traps->traps.freeze_timer>127 ||
        !rules.fire_traps->traps.fire_radius || rules.fire_traps->traps.fire_radius>8 ||
        !rules.fire_traps->traps.fire_rounds || rules.fire_traps->traps.fire_rounds>127))
        throw CodecError("richonline_boss_fire_trap_rules_required");
    if(rules.ice_traps && (mode!=3 || !rules.cards || !rules.ground || !rules.ground_card_visible ||
        !rules.ice_traps->freeze_timer || rules.ice_traps->freeze_timer>127 ||
        !rules.ice_traps->fire_radius || rules.ice_traps->fire_radius>8 ||
        !rules.ice_traps->fire_rounds || rules.ice_traps->fire_rounds>127))
        throw CodecError("richonline_boss_ice_trap_rules_required");
    auto state = std::make_shared<Turns>(Turns{startup.init,std::move(topology),std::move(rules),Phase::loading,1,{},mode});
    state->junction.emplace(startup.init.game_server_id);
    state->active_counter=static_cast<std::uint16_t>(startup.snapshot.calendar_counter);
    return {startup.init,startup.snapshot,startup.envelope,
        [state] { return state->opening(); },
        [state](const Envelope299&,View plain) { return state->action(plain); },
        [state] { state->phase = Phase::closed; state->route = {}; },
        [state] { return state->poll(); },
        [state](View plain) { return state->retired(plain); }};
}
}
