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
#include "lua_wire.hpp"
#include "richonline_pet.hpp"
#include "richonline_pet_chat.hpp"
#include <limits>
#include <chrono>

#include <iterator>
#include <algorithm>
#include <utility>
#include <type_traits>

namespace richnet {
namespace {
enum class Phase { loading, chest_ready, roll, frozen, jailed, jail_exit, moving, stationary, bank, npc, landing, junction, finished, closed };
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
    std::optional<std::chrono::sys_days> feast_tickets_day{},feast_response_day{},feast_status_day{};
    std::optional<std::chrono::steady_clock::time_point> npc_deadline{};
    std::optional<std::uint16_t> npc_pending_counter{},npc_retired_counter{};
    std::array<bool,2> active{true,true};
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
    std::array<RichonlinePetState,2> pets{};
    std::optional<std::int16_t> boss_chest{};
    std::uint8_t chest_turns_left=0;
    std::vector<std::array<std::uint16_t,2>> chest_stops{};

    std::vector<Bytes> finish_chest(std::vector<Bytes> messages,bool picked) {
        auto result=rules.finish_boss_chest(picked);
        messages.insert(messages.end(),std::make_move_iterator(result.begin()),std::make_move_iterator(result.end()));
        if(rules.log) rules.log("richonline_boss_chest_finished picked="+std::to_string(picked)+
            " turns_left="+std::to_string(chest_turns_left));
        phase=Phase::finished;route={};controlled_roll_deadline.reset();
        return messages;
    }
    std::vector<Bytes> open_chest(std::vector<Bytes> messages) {
        if(!rules.finish_boss_chest || !rules.ground || !rules.cards || !active[0] || active[1])
            throw CodecError("richonline_boss_chest_context_invalid");
        std::vector<std::int16_t> candidates;
        for(const auto& cell:topology.cells())
            if(cell.walkable && cell.position!=init.participants[0].position &&
                std::any_of(cell.neighbors.begin(),cell.neighbors.end(),[](const auto& next){return next.has_value();}))
                candidates.push_back(cell.position);
        if(candidates.empty()) throw CodecError("richonline_boss_chest_no_road");
        const auto chosen=rules.random(candidates.size());
        if(chosen>=candidates.size()) throw CodecError("richonline_boss_chest_random_invalid");
        const auto position=candidates[chosen];
        auto ground=rules.ground->prepare(rules.ground->snapshot(),{{position,{32,255,255}}});
        auto inventory=rules.cards->inventory();
        constexpr std::array<std::int16_t,12> removed{1042,1044,1045,1046,1063,1069,1075,1182,1183,500,501,506};
        for(auto& slot:inventory) if(std::find(removed.begin(),removed.end(),slot.card_id)!=removed.end()) slot={};
        Bytes spawn;append_le(spawn,0x420c,2);append_le(spawn,init.game_server_id,2);
        append_le(spawn,static_cast<std::uint16_t>(position),2);messages.push_back(std::move(spawn));
        // 420C ->7F91F0/7F9560清这些状态，医院/监狱和装备免疫保留。
        auto cleaned=status[0];
        richonline_detach_possession(cleaned);cleaned.timed_bomb.reset();cleaned.timed_bomb_owner.reset();
        cleaned.one_step=cleaned.six_steps=cleaned.turtle=cleaned.stay=cleaned.sleepwalking=cleaned.frozen=0;
        cleaned.attack_turns=cleaned.damage_turns=0;
        auto change=rules.npcs ? std::optional{rules.npcs->prepare_status_change(0,status[0],cleaned)} : std::nullopt;
        if(!rules.ground->matches(ground) || (change && !rules.npcs->matches_status_change(*change,status[0])))
            throw CodecError("richonline_boss_chest_state_changed");
        if(!rules.ground->commit_prepared(ground)) std::terminate();
        rules.cards->commit_inventory(inventory);
        if(change) {
            if(!rules.npcs->commit_status_change(*change,status[0])) std::terminate();
        } else status[0]=cleaned;
        relations1472={};
        retire_decision();npc_landing.reset();npc_deadline.reset();npc_pending_counter.reset();
        controlled_roll_deadline.reset();frozen_deadline.reset();jail_deadline.reset();pending_mine_day.reset();
        boss_chest=position;chest_turns_left=3;phase=Phase::chest_ready;route={};
        if(rules.log) rules.log("richonline_boss_chest_open position="+std::to_string(position)+" turns=3");
        return messages;
    }

    bool placement_present(std::uint8_t slot) const {
        if(!active[slot]) return false;
        if(!rules.raw_authority) return true;
        const auto& raw=rules.raw_authority->actor(slot);
        if(!raw.kidnapped1497) throw CodecError("richonline_pet_placement_state_unknown");
        return *raw.kidnapped1497==-1;
    }
    std::optional<std::int16_t> pet_placement(std::uint8_t slot) const {
        if(!pets[slot].equipped || !placement_present(slot)) return {};
        const auto& raw=rules.raw_authority->actor(slot);
        if(!raw.hotel1493) throw CodecError("richonline_pet_placement_state_unknown");
        return *raw.hotel1493==-1 ? pets[slot].known_display_position : std::nullopt;
    }
    std::vector<std::int16_t> placement_reservations() const {
        std::vector<std::int16_t> reserved;
        for(std::uint8_t slot=0;slot<active.size();++slot) if(placement_present(slot)) {
            reserved.push_back(init.participants[slot].position);
            if(const auto position=pet_placement(slot)) reserved.push_back(*position);
        }
        return reserved;
    }
    bool placement_occupied(std::int16_t position) const {
        for(std::uint8_t slot=0;slot<active.size();++slot)
            if(placement_present(slot) && (init.participants[slot].position==position || pet_placement(slot)==position))
                return true;
        return false;
    }
    void reset_pet(std::uint8_t slot) {
        const auto& person=init.participants[slot];
        reset_richonline_pet(pets[slot],topology,person.position,person.direction);
    }
    std::vector<Bytes> sync_stopped_pet() {
        if(!pets[actor].equipped) return {};
        // 合法0011/0012/0028提交后、下一4010之前调用；原客户端附带幽灵转向提示。
        auto message=richonline_pet_stop_sync(init.game_server_id,init.participants[actor].direction);
        reset_pet(actor);
        return {std::move(message)};
    }
    void commit_route_positions(std::size_t end) {
        // 路线已在调用前验证；每格镜像 actor536，途中过61传送口先按出口复位。
        if(end>=route.landings.size() || route.directions.size()!=route.landings.size())
            throw CodecError("richonline_pet_route_progress_invalid");
        auto& person=init.participants[actor];
        for(auto index=authenticated_steps;index<=end;++index) {
            if(index>0 && !controlled_roll_actor()) if(const auto exit=topology.portal_destination(person.position)) {
                person.position=*exit;reset_pet(actor);
            }
            follow_richonline_pet_step(pets[actor],person.position);
            person.position=route.landings[index];person.direction=route.directions[index];
        }
        authenticated_steps=end+1;
    }

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
                &status[slot],capabilities,&active[slot],placement_present(slot),pet_placement(slot)};
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
        messages.insert(messages.end(),std::make_move_iterator(result.messages.begin()),
            std::make_move_iterator(result.messages.end()));
        if(!result.closed) return open_chest(std::move(messages));
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
        if(boss_chest) {
            if(actor!=0 || !chest_turns_left) throw CodecError("richonline_boss_chest_turn_invalid");
            if(--chest_turns_left==0) return finish_chest(std::move(messages),false);
            auto next=begin_turn();
            messages.insert(messages.end(),std::make_move_iterator(next.begin()),std::make_move_iterator(next.end()));
            return messages;
        }
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
            !controlled_roll_actor(),static_cast<bool>(rules.bank) || controlled_roll_actor(),boss_chest.has_value()},rules.random,extend);
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
        // 载具自带的骰子不需要金豆支付上下文，也不能被无支付入口误拒绝。
        if(count<=free_capacity) return prepare_move({},0,count);
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
        bool script_attack=true;
        if(!boss_chest && actor==1 && rules.combat && rules.script)
            script_attack=rules.script->call("boss.can_attack",{{"map",rules.script_map},
                {"actionable",richonline_combat_action_allowed(status[actor])}}).get<bool>();
        if(!boss_chest && actor==1 && rules.combat && script_attack) {
            auto refs=combat_refs();auto attack=rules.combat->boss_turn(refs,actor,rules.combat_random(),rules.log);
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
        reset_pet(actor);
        jail_deadline.reset();
        if(actor==init.local_slot) {
            retired_jail_exit=Decision{active_counter,21};retired_jail_exit_turn=turn_sequence;
        }
        return playable_turn({});
    }
    std::chrono::sys_days game_date() const {
        const std::chrono::year_month_day start{std::chrono::year{init.year},
            std::chrono::month{init.month},std::chrono::day{init.day}};
        return std::chrono::sys_days{start}+std::chrono::days{complete_rounds};
    }
    std::optional<std::size_t> feast_slot() const {
        const std::chrono::year_month_day date{game_date()};
        const auto year=static_cast<int>(date.year());
        if(year<2004 || year>=2035) return {};
        const auto& dates=rules.feast_dates[static_cast<std::size_t>(year-2004)];
        // NEW7D8DE0 selects the first match before applying the mode gate.
        for(std::size_t slot=0;slot<dates.size();++slot)
            if(dates[slot][0]==static_cast<unsigned>(date.month()) &&
                dates[slot][1]==static_cast<unsigned>(date.day())) return slot;
        return {};
    }
    void sync_feast_tickets() {
        if(actor!=1 || !rules.ledger || feast_tickets_day==game_date()) return;
        const auto slot=feast_slot();
        if(!slot) return;
        const auto grant=rules.script ? rules.script->call("feast.tickets",{{"slot",*slot}}).get<std::uint32_t>() :
            *slot==0 ? 111U : *slot==6 ? 180U : *slot==8 ? 55U : *slot==11 ? 99U : 0U;
        if(grant>0x7fffffffU) throw CodecError("lua_feast_tickets_invalid");
        if(!grant) return;
        std::vector<RichonlineGameFundsUpdate> updates;
        for(std::uint8_t target=0;target<active.size();++target) if(active[target]) {
            const auto before=rules.ledger->snapshot(target);
            auto after=before.funds;
            if(after.tickets>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())-grant)
                throw CodecError("richonline_feast_ticket_overflow");
            after.tickets+=grant;
            updates.push_back({target,before,after});
        }
        if(!updates.empty() && !rules.ledger->commit_batch(updates,[]{return true;}))
            throw CodecError("richonline_feast_ledger_rejected");
        feast_tickets_day=game_date();
        // These four festivals already apply6062 locally; do not send a second grant.
        if(rules.log) {
            auto detail="richonline_feast_tickets day="+std::to_string(complete_rounds)+
                " slot="+std::to_string(*slot)+" grant="+std::to_string(grant);
            for(const auto& update:updates)
                detail+=" actor="+std::to_string(update.actor)+" before="+
                    std::to_string(update.before.funds.tickets)+" after="+std::to_string(update.after.tickets);
            rules.log(detail);
        }
    }
    void append_feast_response(std::vector<Bytes>& messages) {
        if(actor!=init.local_slot || feast_response_day==game_date()) return;
        const auto slot=feast_slot();
        if(!slot) return;
        if(*slot==1 || *slot==2 || *slot==4 || *slot==5 || *slot==9) {
            if(!rules.cards) throw CodecError("richonline_feast_cards_required");
            const auto reward=rules.cards->prepare_random_reward();
            Bytes packet;append_le(packet,0x40a0,2);append_le(packet,init.game_server_id,2);
            // The synthetic BOSS has no authoritative hand. Its gift field stays -1.
            for(std::uint8_t target=0;target<8;++target)
                append_le(packet,static_cast<std::uint16_t>(target<active.size() &&
                    target==init.local_slot && active[target] ? reward.card : -1),2);
            messages.push_back(std::move(packet));
            const auto changed=reward.inventory!=rules.cards->inventory();
            rules.cards->commit_inventory(reward.inventory);
            feast_response_day=game_date();
            if(rules.log) rules.log("richonline_feast_card day="+std::to_string(complete_rounds)+
                " slot="+std::to_string(*slot)+" actor="+std::to_string(actor)+
                " card="+std::to_string(reward.card)+" inventory_changed="+std::to_string(changed)+
                " policy=native-uniform-playable-resource-cards-v1");
        } else if(*slot==3) {
            if(!rules.ledger || !rules.random) throw CodecError("richonline_feast_luck_required");
            Bytes packet;append_le(packet,0x40a1,2);append_le(packet,init.game_server_id,2);
            std::vector<RichonlineGameFundsUpdate> updates;
            for(std::uint8_t target=0;target<8;++target) {
                auto win=false;
                if(target<active.size() && active[target]) {
                    const auto selected=rules.random(2);
                    if(selected>=2) throw CodecError("richonline_feast_random_invalid");
                    win=selected!=0;
                    const auto before=rules.ledger->snapshot(target);
                    auto after=before.funds;
                    if(win) {
                        if(after.tickets>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()-41))
                            throw CodecError("richonline_feast_ticket_overflow");
                        after.tickets+=41;
                    } else after.tickets-=std::min(after.tickets,41U);
                    updates.push_back({target,before,after});
                }
                packet.push_back(win ? 1 : 0);
            }
            messages.push_back(std::move(packet));
            if(!updates.empty() && !rules.ledger->commit_batch(updates,[]{return true;}))
                throw CodecError("richonline_feast_ledger_rejected");
            feast_response_day=game_date();
            if(rules.log) {
                auto detail="richonline_feast_luck day="+std::to_string(complete_rounds)+
                    " policy=native-uniform-win-loss-41-v1";
                for(const auto& update:updates)
                    detail+=" actor="+std::to_string(update.actor)+" before="+
                        std::to_string(update.before.funds.tickets)+" after="+std::to_string(update.after.tickets);
                rules.log(detail);
            }
        }
    }
    void sync_feast_status() {
        if(actor!=1 || feast_status_day==game_date() || feast_slot()!=12) return;
        auto after=status;
        std::array<std::optional<RichonlineNpcSession::PreparedStatusChange>,2> clocks;
        for(std::uint8_t target=0;target<active.size();++target) if(active[target]) {
            const auto npc=after[target].possession;
            // NEW7BDD50 /6947C0 removes only harmful possession;6065 clears the bomb.
            if(npc==1 || npc==2 || npc==6 || npc==7 || npc==18)
                richonline_detach_possession(after[target]);
            after[target].timed_bomb.reset();after[target].timed_bomb_owner.reset();
            if(rules.npcs && after[target]!=status[target])
                clocks[target]=rules.npcs->prepare_status_change(target,status[target],after[target]);
        }
        for(std::uint8_t target=0;target<clocks.size();++target)
            if(clocks[target] && !rules.npcs->matches_status_change(*clocks[target],status[target]))
                throw CodecError("richonline_feast_status_stale");
        for(std::uint8_t target=0;target<clocks.size();++target)
            if(clocks[target] && !rules.npcs->commit_status_change(*clocks[target],status[target]))
                std::terminate();
        status=after;feast_status_day=game_date();
        if(rules.log) rules.log("richonline_feast_status day="+std::to_string(complete_rounds)+
            " slot=12 harmful_possession_and_timed_bombs_cleared=1");
    }
    std::vector<Bytes> begin_turn() {
        // 7C0C50在回合入口先刷新属性；光环6060尚未消费，回血取进入本回合时的现金。
        const auto equipment_heal=rules.equipment_healing && rules.ledger ?
            rules.equipment_healing(actor,rules.ledger->snapshot(actor).funds.cash):0U;
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
        if(!boss_chest) {sync_feast_tickets();sync_feast_status();}
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
        if(boss_chest) {
            // 保留已淘汰BOSS的anchor1：客户端2次日历倒计时不介入，服务端数满3个玩家回合。
            if(equipment_heal) {
                const auto before=rules.ledger->snapshot(actor);auto after=before.funds;
                if(after.cash>0x7fffffffU-equipment_heal) throw CodecError("richonline_equipment_healing_cash_overflow");
                after.cash+=equipment_heal;rules.ledger->commit(actor,before,after);
            }
            if(rules.raw_authority) {
                const auto& raw=rules.raw_authority->actor(actor);
                if(raw.jail1495 && *raw.jail1495!=-1) {
                    phase=*raw.jail1495==0 ? Phase::jail_exit : Phase::jailed;
                    if(phase==Phase::jailed) jail_deadline=rules.now()+std::chrono::milliseconds{1800};
                    return messages;
                }
            }
            return playable_turn(std::move(messages));
        }
        if(actor==1 && rules.property) {
            auto enabled=true;
            if(rules.raw_authority) {
                const auto scripted=rules.raw_authority->game().scripted_event83830;
                if(!scripted) throw CodecError("richonline_building_buff_scripted_state_unknown");
                enabled=*scripted==-1;
            }
            rules.property->advance_building_buffs(complete_rounds,active,enabled,rules.log);
        }
        append_feast_response(messages);
        std::vector<RichonlineGameFundsUpdate> turn_funds;
        std::vector<std::uint8_t> aura_bankrupt;
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
            turn_funds=std::move(aura.updates);
            aura_bankrupt=std::move(aura.bankrupt_actors);
        }
        std::optional<std::array<std::uint32_t,2>> healed_cash;
        if(equipment_heal && aura_bankrupt.empty()) {
            auto before=rules.ledger->snapshot(actor);
            for(const auto& update:turn_funds) if(update.actor==actor) {
                if(before!=update.before) throw CodecError("richonline_game_ledger_conflict");
                if(before.funds!=update.after) {
                    if(before.revision==std::numeric_limits<std::uint64_t>::max())
                        throw CodecError("richonline_game_ledger_revision_exhausted");
                    before={update.after,before.revision+1};
                }
            }
            auto after=before.funds;
            if(after.cash>0x7fffffffU-equipment_heal) throw CodecError("richonline_equipment_healing_cash_overflow");
            healed_cash=std::array{after.cash,after.cash+equipment_heal};
            after.cash+=equipment_heal;
            turn_funds.push_back({actor,before,after});
        }
        // 光环和回血各算一笔收入，按队列顺序校验后原子提交，不能用净额抵消回血收入。
        if(!turn_funds.empty() && !rules.ledger->commit_sequence(turn_funds,[]{return true;}))
            throw CodecError("richonline_boss_turn_funds_rejected");
        if(!aura_bankrupt.empty())
            return terminal(std::move(messages),std::move(aura_bankrupt),RichonlineTerminalReason::npc_aura);
        if(healed_cash) {
            // 不发现金变动包：4010已让客户端排队同一笔6060，重发会造成双倍回血。
            if(rules.log) rules.log("richonline_equipment_healing actor="+std::to_string(actor)+
                " turn="+std::to_string(turn_sequence)+" amount="+std::to_string(equipment_heal)+
                " before="+std::to_string((*healed_cash)[0])+" after="+std::to_string((*healed_cash)[1]));
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
            auto refs=combat_refs();
            auto bases=rules.combat->missile_base_round(refs,complete_rounds,rules.random,rules.log);
            messages.insert(messages.end(),std::make_move_iterator(bases.packets.begin()),
                std::make_move_iterator(bases.packets.end()));
            if(!bases.bankrupt_actors.empty())
                return terminal(std::move(messages),std::move(bases.bankrupt_actors),RichonlineTerminalReason::missile_base);
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
        const auto starts=placement_reservations();
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
        if(boss_chest && opcode==0x11) {
            const auto request=std::get<RichonlineMoveStop11>(parse_richonline_movement_request(plain));
            for(const auto& stop:chest_stops)
                if(request.calendar_counter==stop[0] && static_cast<std::uint16_t>(request.endpoint)==stop[1]) return true;
        }
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
        if(boss_chest || controlled_roll_actor()) return {};
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
        commit_route_positions(end);
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
        commit_route_positions(completed-1);
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
    std::vector<Bytes> complete_portal_landing(const PendingLanding& landing,std::int16_t destination,
        std::vector<Bytes> messages) {
        auto& person=init.participants[actor];
        person.position=destination;person.direction=landing.heading;
        reset_pet(actor);
        landing_counter=landing.counter;route={};checkpoint_cursor=0;authenticated_steps=0;
        if(rules.combat && rules.combat->has_mine(destination)) {
            // Both portal animations only relocate;4017 starts the destination mine effect.
            auto refs=combat_refs();auto explosion=rules.combat->stepped_mine(refs,destination,true);
            messages.insert(messages.end(),std::make_move_iterator(explosion.packets.begin()),
                std::make_move_iterator(explosion.packets.end()));
            if(rules.log) rules.log("richonline_teleport_mine actor="+std::to_string(actor)+
                " source="+std::to_string(landing.position)+" position="+std::to_string(destination)+
                " bankrupt_count="+std::to_string(explosion.bankrupt_actors.size()));
            if(!explosion.bankrupt_actors.empty())
                return terminal(std::move(messages),std::move(explosion.bankrupt_actors),
                    RichonlineTerminalReason::stepped_mine);
        }
        return advance(std::move(messages));
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
                return complete_portal_landing(landing,destination,std::move(messages));
            }
            if(portal->continuation==RichonlinePortalContinuation::awaiting_server_continuation) {
                const auto& exit=topology.cell(portal->authoritative_position);
                if (portal->authoritative_position==landing.position || !exit.walkable ||
                    exit.static_type!=cell.static_type ||
                    (cell.static_type==61 && topology.portal_destination(landing.position)!=portal->authoritative_position))
                    throw CodecError("richonline_boss_portal_destination_invalid");
                return complete_portal_landing(landing,portal->authoritative_position,
                    landing.sent_stop ? std::vector<Bytes>{} : std::vector<Bytes>{std::move(entrance)});
            }
            if(portal->continuation!=RichonlinePortalContinuation::property_phase2 ||
                portal->authoritative_position!=landing.position)
                throw CodecError("richonline_boss_portal_continuation_invalid");
        }
        const auto context=landing_context(landing.position);
        const auto native_landing=[&]() {
            auto card_result=richonline_news_landing_allowed(context) && rules.chance_landing ? rules.chance_landing(context) : std::nullopt;
            if(!richonline_landing_controlled(status[actor]) && !card_result && rules.cards) card_result=rules.cards->land(context);
            return card_result ? std::move(*card_result) : rules.landed(context);
        };
        std::optional<RichonlineLandingResult> scripted_result;
        if(rules.script) {
            const LuaBindings api{{"tile.native",[&](const LuaValue&) {
                if(scripted_result) throw CodecError("lua_native_landing_already_called");
                scripted_result=native_landing();return LuaValue(true);
            }}};
            rules.script->call("tile.land",{{"type",context.static_type},{"position",context.position},
                {"actor",context.actor_slot},{"map",rules.script_map}},api);
            if(!scripted_result) throw CodecError("lua_landing_continuation_required");
        } else scripted_result=native_landing();
        auto result=std::move(*scripted_result);
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
    struct PreparedHibernate {
        RichonlineHibernatePlan plan;
        std::array<std::optional<RichonlineNpcSession::PreparedStatusChange>,2> clocks;
        AcceptedHibernate accepted;
    };
    PreparedHibernate prepare_hibernate(View plain,const RichonlineHibernateSnapshot& before) {
        const auto request=decode_richonline_hibernate164(plain);require_local_controls();
        if(phase!=Phase::roll || actor!=init.local_slot || !rules.hibernate || !rules.cards)
            throw CodecError("richonline_boss_hibernate_out_of_phase");
        PreparedHibernate prepared{plan_richonline_hibernate(request,init.game_server_id,
            static_cast<std::int8_t>(actor),rules.cards->map_name(),*rules.hibernate->resources,
            rules.hibernate->rules,before),{}, {}};
        for(std::uint8_t slot=0;slot<status.size();++slot)
            if(rules.npcs && before.actors[slot].status!=prepared.plan.after.actors[slot].status)
                prepared.clocks[slot]=rules.npcs->prepare_status_change(slot,before.actors[slot].status,
                    prepared.plan.after.actors[slot].status);
        std::copy(plain.begin(),plain.end(),prepared.accepted.request.begin());
        prepared.accepted.turn=turn_sequence;
        return prepared;
    }
    bool hibernate_matches(const PreparedHibernate& prepared) const {
        if(turn_sequence!=prepared.accepted.turn || hibernate_snapshot()!=prepared.plan.before) return false;
        for(std::uint8_t slot=0;slot<status.size();++slot)
            if(prepared.clocks[slot] && !rules.npcs->matches_status_change(*prepared.clocks[slot],status[slot]))
                return false;
        return true;
    }
    void commit_hibernate(PreparedHibernate& prepared) noexcept {
        // 所有角色、保护卡、同盟和附身时钟先准备并复核；此串行提交段不再分配或读取外部状态。
        for(std::uint8_t slot=0;slot<status.size();++slot) {
            if(prepared.clocks[slot]) {
                if(!rules.npcs->commit_status_change(*prepared.clocks[slot],status[slot])) std::terminate();
            } else status[slot]=prepared.plan.after.actors[slot].status;
            relations1472[slot]=prepared.plan.after.actors[slot].relations1472;
        }
        rules.cards->commit_inventory(prepared.plan.after.actors[init.local_slot].inventory.main);
        accepted_hibernate=prepared.accepted;
    }
    std::vector<Bytes> hibernate(View plain) {
        auto prepared=prepare_card(164,[&] {return prepare_hibernate(plain,hibernate_snapshot());});
        if(!prepared) return {encode_richonline_dice_recovery400b(init.game_server_id)};
        std::vector<Bytes> messages{prepared->plan.response40f4};
        if(!hibernate_matches(*prepared)) throw CodecError("richonline_boss_hibernate_snapshot_changed");
        commit_hibernate(*prepared);
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
        std::optional<RichonlineRawAuthority::PreparedJailEntry> jail_entry;
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
                    if(rules.jail_days>127) throw CodecError("richonline_frame_jail_days_invalid");
                    jail_entry=rules.raw_authority->prepare_jail_entry(target,static_cast<std::int8_t>(rules.jail_days));
                    after_participants[target].position=(*topology.jail_positions())[0];
                    after_status[target].stay=0; // NEW7F8160 clears1496.
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
                const std::uint32_t award=rules.script ?
                    rules.script->call("card.lottery_award",LuaValue::object()).get<std::uint32_t>() : 15000U;
                if(award>0x7fffffffU) throw CodecError("lua_lottery_award_invalid");
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
                (jail_entry && !rules.raw_authority->matches_jail_entry(*jail_entry)) ||
                (clock && !rules.npcs->matches_status_change(*clock,status[target]))) return false;
            if(ground && !rules.ground->commit_prepared(*ground)) std::terminate();
            if(clock && !rules.npcs->commit_status_change(*clock,status[target])) std::terminate();
            if(jail_entry && !rules.raw_authority->commit_jail_entry(*jail_entry)) std::terminate();
            status=after_status;relations1472=after_relations;
            init.participants=std::move(after_participants);rules.cards->commit_inventory(inventory);
            if(opcode==143) reset_pet(actor);
            if(opcode==117 && jail_entry) reset_pet(target);
            if(opcode==161) for(std::uint8_t slot=0;slot<active.size();++slot)
                if(active[slot] && raw_available(slot) && !status[slot].frozen) reset_pet(slot);
            return true;
        };
        if(funds.empty() ? !commit() : !rules.ledger->commit_batch(funds,commit))
            throw CodecError("richonline_auxiliary_card_stale");
        return messages;
    }
    std::vector<Bytes> script_action(View plain) {
        if(boss_chest && plain.size()>=2 && read_le(plain.first(2))==0x11 && retired(plain)) return {};
        if(boss_chest && plain.size()>=2) {
            const auto opcode=read_le(plain.first(2));
            if(opcode>=92 && opcode!=103 && opcode!=137 && opcode!=138 && opcode!=139 &&
                opcode!=140 && opcode!=152 && opcode!=160)
                return {encode_richonline_dice_recovery400b(init.game_server_id)};
        }
        if(plain.size()>=2 && read_le(plain.first(2))==66) {
            try {
                if(phase==Phase::loading || phase==Phase::closed || phase==Phase::finished)
                    throw CodecError("richonline_pet_chat_out_of_phase");
                return {richonline_pet_chat_response(plain,init.game_server_id,init.local_slot,pets[init.local_slot].equipped)};
            } catch(const CodecError& error) {
                if(rules.log) rules.log(std::string("richonline_pet_chat_refused reason=")+error.what());
                return {};
            }
        }
        if(!rules.script) return action(plain);
        if(plain.size()>=2 && read_le(plain.first(2))==164 && retired(plain)) return {};
        bool called=false;
        bool database_called=false;
        std::optional<RichonlineBossCards::PreparedConsumption> script_consumption;
        std::optional<RichonlineBossCards::PreparedShuffle> script_shuffle;
        std::optional<RichonlineBossProperty::PreparedCombat> script_property;
        std::optional<RichonlineBossProperty::PreparedStreetEffect> script_street;
        std::optional<RichonlineGroundObjects::Prepared> script_ground;
        std::optional<RichonlineGroundSnapshot> script_ground_snapshot;
        std::vector<RichonlineGameFundsUpdate> script_funds;
        std::optional<std::uint8_t> script_break_alliance;
        std::optional<std::pair<std::uint8_t,std::uint8_t>> script_set_alliance;
        struct ScriptMotion {
            RichonlineMotionCardPlan card;
            std::uint8_t target;
            std::optional<RichonlineNpcSession::PreparedStatusChange> clock;
            std::optional<PreparedMove> movement;
        };
        std::optional<ScriptMotion> script_motion;
        struct ScriptMovement {
            PreparedMove move;
            std::uint8_t actor,heading;
            std::uint16_t calendar;
            std::uint64_t turn;
            std::int16_t position;
            RichonlineActorStatus status;
            std::optional<RichonlineGroundObjects::Prepared> ground_version;
        };
        std::optional<ScriptMovement> script_movement;
        std::optional<std::uint8_t> script_clear_relations;
        struct ScriptStatus {
            std::uint8_t target;
            RichonlineActorStatus before,after;
            std::optional<RichonlineNpcSession::PreparedStatusChange> clock;
        };
        std::optional<ScriptStatus> script_status;
        struct ScriptJail {
            std::uint8_t source,target;
            std::uint16_t calendar;
            std::uint64_t turn;
            std::int16_t before_position,after_position;
            RichonlineActorStatus before_status,after_status;
            RichonlineRawAuthority::PreparedJailEntry raw;
            std::optional<RichonlineNpcSession::PreparedStatusChange> clock;
            bool applied;
            Bytes response;
        };
        std::optional<ScriptJail> script_jail;
        struct ScriptDismiss {
            std::uint8_t source,target;
            std::uint16_t calendar;
            std::uint64_t turn;
            RichonlineActorStatus source_status;
            RichonlineRawActorState target_raw;
            Bytes response;
        };
        std::optional<ScriptDismiss> script_dismiss;
        struct ScriptGodCard {
            std::uint8_t actor;
            std::int8_t npc;
            std::uint16_t calendar;
            std::uint64_t turn;
            std::int16_t position;
            RichonlineChanceInventory consumed_inventory;
            Bytes confirmation;
            std::optional<RichonlineFortuneRewardPlan> reward;
            std::optional<std::chrono::steady_clock::time_point> deadline;
        };
        std::optional<ScriptGodCard> script_god_card;
        struct ScriptSummonSnapshot {
            std::uint8_t source,target;
            std::uint16_t calendar;
            std::uint64_t turn;
            std::int16_t source_position,target_position;
            RichonlineActorStatus source_status,target_status;
            RichonlineRawActorState target_raw;
            std::vector<RichonlineSummonedNpc> candidates;
        };
        std::optional<ScriptSummonSnapshot> script_summon_snapshot;
        std::optional<RichonlineNpcSession::PreparedDeityCard> script_summon;
        std::optional<std::chrono::steady_clock::time_point> script_summon_deadline;
        std::optional<std::chrono::steady_clock::time_point> script_summon_roll_deadline;
        std::string script_summon_log;
        std::optional<RichonlineHibernateSnapshot> script_hibernate_snapshot;
        std::optional<PreparedHibernate> script_hibernate;
        struct ScriptAttack {
            RichonlineCombatBridge::PreparedHumanAttack prepared;
            std::uint8_t actor;
            std::uint16_t calendar;
            std::uint64_t turn;
            RichonlineChanceInventory consumed_inventory;
        };
        std::optional<ScriptAttack> script_attack;
        std::optional<std::array<RichonlineRawActorState,8>> script_poison_raw;
        bool script_inventory_cleared=false;
        bool script_route_previewed=false;
        struct ScriptPosition {std::uint8_t slot;std::int16_t before,after;};
        std::vector<ScriptPosition> script_positions;
        bool script_positions_prepared=false;
        const auto ground_snapshot=[&]() -> const RichonlineGroundSnapshot& {
            if(!rules.ground) throw CodecError("lua_ground_authority_required");
            if(!script_ground_snapshot) script_ground_snapshot=rules.ground->snapshot();
            return *script_ground_snapshot;
        };
        // 单格与批量放置共用准备器；只构造版本化计划，不提前修改地面或手牌。
        const auto prepare_ground=[&](const LuaValue& objects) {
            if(called || database_called || !script_consumption || script_ground || !rules.ground || status[actor].frozen)
                throw CodecError("lua_ground_prepare_out_of_scope");
            if(!objects.is_array() || objects.size()>topology.cells().size())
                throw CodecError("lua_ground_objects_invalid");
            const auto& before=ground_snapshot();
            auto after=before.objects;
            for(const auto& object:objects) {
                const auto integer=[&](const char* key,std::int64_t low,std::int64_t high) {
                    const auto& value=object.at(key);
                    if(!value.is_number_integer() || value<low || value>high)
                        throw CodecError("lua_ground_argument_invalid");
                    return value.get<std::int64_t>();
                };
                const auto position=static_cast<std::int16_t>(integer("position",0,32767));
                if(static_cast<std::size_t>(position)>=topology.cells().size() || !topology.cell(position).walkable)
                    throw CodecError("lua_ground_position_invalid");
                if(placement_occupied(position)) throw CodecError("richonline_ground_card_target_actor_occupied");
                if(!after.emplace(position,RichonlineGroundObject{static_cast<std::int8_t>(integer("npc",0,127)),
                    static_cast<std::uint8_t>(integer("byte7",0,255)),static_cast<std::uint8_t>(integer("byte8",0,255))}).second)
                    throw CodecError("richonline_ground_card_target_dynamic_occupied");
            }
            script_ground=rules.ground->prepare(before,after);
            return LuaValue{};
        };
        const auto encode=[](const std::vector<Bytes>& messages) {
            auto result=LuaValue::array();
            for(const auto& packet:messages) result.push_back(lua_bytes(View(packet)));
            return result;
        };
        LuaBindings api{
            {"game.native",[&](const LuaValue&) {
                if(std::exchange(called,true)) throw CodecError("lua_native_request_already_called");
                if(script_consumption || database_called) throw CodecError("lua_cannot_mix_native_and_prepared_action");
                return encode(action(plain));
            }},
            {"card.prepare",[&](const LuaValue& args) {
                require_local_controls();
                if(called || database_called || script_consumption || phase!=Phase::roll || actor!=init.local_slot || !active[actor] || !rules.cards ||
                    plain.size()<6 || plain[4]>=8 || plain[5]!=0 || read_le(plain.subspan(2,2))!=active_counter)
                    throw CodecError("lua_card_request_invalid");
                if(!args.at("card").is_number_integer()) throw CodecError("lua_card_id_invalid");
                const auto id=args.at("card").get<std::int64_t>();
                if(id<1||id>32767) throw CodecError("lua_card_id_invalid");
                script_consumption=rules.cards->prepare_consumption(static_cast<std::int8_t>(plain[4]),static_cast<std::int16_t>(id));
                if(!script_consumption) throw CodecError("lua_card_not_owned");
                return LuaValue{{"slot",plain[4]},{"bank",plain[5]}};
            }},
            {"combat.prepare_attack",[&](const LuaValue& args) {
                require_local_controls();
                if(called || database_called || !script_consumption || script_attack || !rules.combat ||
                    phase!=Phase::roll || actor!=init.local_slot || !active[actor])
                    throw CodecError("lua_attack_prepare_out_of_scope");
                const auto request=parse_richonline_target_card(plain);
                const auto& card=args.at("card");const auto& target=args.at("target");
                if(!card.is_number_integer() || card!=script_consumption->card_id ||
                    !target.is_number_integer() || target!=request.target)
                    throw CodecError("lua_attack_argument_mismatch");
                auto refs=combat_refs();
                auto prepared=rules.combat->prepare_human_attack(refs,request,active_counter,*script_consumption);
                script_attack=ScriptAttack{std::move(prepared),actor,active_counter,turn_sequence,
                    script_consumption->remaining_inventory};
                return LuaValue{};
            }},
            {"research.poison_rules",[&](const LuaValue&) {
                if(!rules.poison || !rules.combat || !rules.poison_raw_actor)
                    throw CodecError("richonline_boss_poison_authority_required");
                return LuaValue{{"range",rules.poison->range}};
            }},
            {"combat.prepare_poison",[&](const LuaValue& args) {
                require_local_controls();
                if(called || database_called || !script_consumption || script_consumption->card_id!=1182 ||
                    script_attack || !rules.poison || !rules.combat || !rules.poison_raw_actor ||
                    phase!=Phase::roll || actor!=init.local_slot || plain.size()!=8 || read_le(plain.first(2))!=156)
                    throw CodecError("lua_poison_prepare_out_of_scope");
                const auto request=decode_richonline_research_card(plain);
                const auto expected=richonline_poison_map_footprint(topology,init.participants[actor].position,rules.poison->range);
                const auto& footprint=args.at("footprint");
                if(!footprint.is_array() || footprint.size()!=expected.size())
                    throw CodecError("lua_poison_footprint_invalid");
                for(std::size_t i=0;i<expected.size();++i) {
                    const auto& cell=footprint.at(i);
                    if(!cell.at("position").is_number_integer() || !cell.at("layer").is_number_integer() ||
                        cell.at("position")!=expected[i].position || cell.at("layer")!=expected[i].attenuation_layer)
                        throw CodecError("lua_poison_footprint_mismatch");
                }
                const RichonlineResearchCardContext context{init.game_server_id,active_counter,
                    static_cast<std::int8_t>(actor),static_cast<std::int8_t>(init.local_slot),true,
                    active[actor] && !richonline_landing_controlled(status[actor])};
                std::array<RichonlineRawActorState,8> raw{};
                for(std::uint8_t slot=0;slot<active.size();++slot) raw[slot]=rules.poison_raw_actor(slot);
                auto refs=combat_refs();
                auto prepared=rules.combat->prepare_poison_card(refs,request,context,poison_use_count,
                    *rules.poison,expected,raw,relations1472);
                script_attack=ScriptAttack{std::move(prepared),actor,active_counter,turn_sequence,
                    script_consumption->remaining_inventory};
                script_poison_raw=std::move(raw);
                return LuaValue{};
            }},
            {"combat.prepare_detonation",[&](const LuaValue&) {
                require_local_controls();
                if(called || database_called || !script_consumption || script_attack || !rules.combat ||
                    script_consumption->card_id!=501 || phase!=Phase::roll || actor!=init.local_slot || !active[actor] ||
                    plain.size()!=8 || read_le(plain.first(2))!=159)
                    throw CodecError("lua_detonation_prepare_out_of_scope");
                // 651050没有初始化请求+6/+7，爆炸根必须从真实地雷及角色可视范围计算。
                auto refs=combat_refs();
                auto prepared=rules.combat->prepare_detonation_card(refs,*script_consumption);
                auto effects=LuaValue::array();
                const auto& packets=prepared.packets();
                // Lua构造第一包40EF；后续连锁与存活恢复包由战斗计划提供，不能自行漏发或重排。
                for(std::size_t i=1;i<packets.size();++i) effects.push_back(lua_bytes(View(packets[i])));
                script_attack=ScriptAttack{std::move(prepared),actor,active_counter,turn_sequence,
                    script_consumption->remaining_inventory};
                return effects;
            }},
            {"combat.prepare_timed_bomb",[&](const LuaValue& args) {
                require_local_controls();
                if(called || database_called || !script_consumption || script_attack || !rules.combat ||
                    !rules.timed_bombs || script_consumption->card_id!=1045 ||
                    phase!=Phase::roll || actor!=init.local_slot || !active[actor])
                    throw CodecError("lua_timed_bomb_prepare_out_of_scope");
                const auto request=decode_richonline_timed_bomb110(plain);
                const auto& target=args.at("target");
                if(!target.is_number_integer() || target!=request.target_actor)
                    throw CodecError("lua_timed_bomb_target_mismatch");
                const auto context=timed_context(init.participants[actor].position);
                auto refs=combat_refs();
                auto prepared=rules.combat->prepare_timed_bomb_card(refs,actor,request,active_counter,
                    *rules.timed_bombs->resources,context.raw,*script_consumption,rules.timed_bombs->response_opaque7);
                script_attack=ScriptAttack{std::move(prepared),actor,active_counter,turn_sequence,
                    script_consumption->remaining_inventory};
                // +7来自房间协议配置，不能照搬请求未使用的尾字节。计时器由核心资源规则负责。
                return LuaValue{{"response_opaque7",rules.timed_bombs->response_opaque7}};
            }},
            {"hibernate.snapshot",[&](const LuaValue&) {
                if(called || database_called || !script_consumption || script_consumption->card_id!=506 ||
                    plain.size()!=6 || read_le(plain.first(2))!=164 || script_hibernate_snapshot)
                    throw CodecError("lua_hibernate_snapshot_out_of_scope");
                script_hibernate_snapshot=hibernate_snapshot();
                auto actors=LuaValue::array();
                for(std::size_t slot=0;slot<script_hibernate_snapshot->actors.size();++slot) {
                    const auto& target=script_hibernate_snapshot->actors[slot];
                    actors.push_back({{"slot",slot},{"present",target.present},{"hotel",target.raw1493},
                        {"hospital",target.raw1494},{"jail",target.raw1495},{"kidnapped",target.raw1497},
                        {"frozen",target.status.frozen}});
                }
                return LuaValue{{"actor",actor},{"actors",actors},{"frozen_turns",rules.hibernate->rules.frozen_turns}};
            }},
            {"hibernate.prepare",[&](const LuaValue& args) {
                if(called || database_called || !script_consumption || !script_hibernate_snapshot || script_hibernate)
                    throw CodecError("lua_hibernate_prepare_out_of_scope");
                const auto& targets=args.at("targets");const auto& turns=args.at("frozen_turns");
                if(!targets.is_array() || targets.empty() || targets.size()>7 || !turns.is_number_integer() ||
                    turns!=rules.hibernate->rules.frozen_turns)
                    throw CodecError("lua_hibernate_policy_invalid");
                auto prepared=prepare_hibernate(plain,*script_hibernate_snapshot);
                auto expected=LuaValue::array();
                for(std::size_t slot=0;slot<prepared.plan.effects.size();++slot)
                    if(prepared.plan.effects[slot]!=RichonlineHibernateEffect::ineligible &&
                        prepared.plan.effects[slot]!=RichonlineHibernateEffect::requester) expected.push_back(slot);
                // Lua 选目标；核心按客户端规则复核完整列表，免疫/保护卡仍在同一快照内解析。
                for(const auto& target:targets) if(!target.is_number_integer())
                    throw CodecError("lua_hibernate_target_invalid");
                if(targets!=expected || script_consumption->source_inventory!=prepared.plan.before.actors[actor].inventory.main ||
                    script_consumption->remaining_inventory!=prepared.plan.after.actors[actor].inventory.main)
                    throw CodecError("lua_hibernate_plan_mismatch");
                script_hibernate=std::move(prepared);
                return LuaValue{};
            }},
            {"route.prepare_move",[&](const LuaValue& args) {
                require_local_controls();
                if(called || database_called || !script_consumption || script_movement ||
                    phase!=Phase::roll || actor!=init.local_slot || !active[actor])
                    throw CodecError("lua_route_prepare_out_of_scope");
                const auto& steps=args.at("steps");
                if(!steps.is_number_integer() || steps<1 || steps>6)
                    throw CodecError("lua_route_steps_invalid");
                const auto& person=init.participants[actor];
                // 只校验地面版本，不提交此无变化计划；路障等仍在实际经过时消费。
                auto ground_version=rules.ground ? std::optional{rules.ground->prepare(
                    ground_snapshot(),ground_snapshot().objects)} : std::nullopt;
                auto movement=prepare_move(steps.get<std::uint8_t>());
                auto packets=encode(movement.messages);
                script_movement=ScriptMovement{std::move(movement),actor,person.direction,
                    active_counter,turn_sequence,person.position,status[actor],std::move(ground_version)};
                return packets;
            }},
            {"motion.prepare",[&](const LuaValue& args) {
                if(called || database_called || !script_consumption || script_motion || !rules.motion_cards || !rules.cards)
                    throw CodecError("lua_motion_prepare_out_of_scope");
                const auto card_id=args.at("card").get<std::int64_t>();
                const auto target_value=args.at("target");
                if(card_id<1 || card_id>32767 || !target_value.is_number_integer()) throw CodecError("lua_motion_argument_invalid");
                const auto target=target_value.get<std::int8_t>();
                const auto expected_card=[&] {
                    switch(read_le(plain.first(2))) {
                    case 104:return std::int16_t{1039}; case 105:return std::int16_t{1040}; case 106:return std::int16_t{1041};
                    case 107:return std::int16_t{1042}; case 136:return std::int16_t{1079}; case 141:return std::int16_t{1084};
                    default: throw CodecError("lua_motion_opcode_invalid");
                    }
                }();
                if(card_id!=expected_card || phase!=Phase::roll || actor!=init.local_slot || !active[actor]) throw CodecError("lua_motion_card_out_of_phase");
                const auto request=parse_richonline_motion_card(plain);
                if(request.target_actor!=target || target<0 || target>=static_cast<std::int8_t>(init.participants.size())) throw CodecError("lua_motion_target_invalid");
                const auto& person=init.participants[static_cast<std::size_t>(target)];
                const RichonlineMotionCardTarget before{target,person.position,person.direction,status[static_cast<std::size_t>(target)],active[static_cast<std::size_t>(target)],raw_available(static_cast<std::uint8_t>(target))};
                auto card=plan_richonline_motion_card(init.game_server_id,request,active_counter,static_cast<std::int8_t>(actor),before,*rules.motion_cards,topology,rules.random,*rules.cards);
                if(card.consumption.source_inventory!=script_consumption->source_inventory || card.consumption.slot!=script_consumption->slot || card.consumption.card_id!=script_consumption->card_id) throw CodecError("lua_motion_consumption_mismatch");
                auto inventory=card.consumption.remaining_inventory;
                if(static_cast<std::uint16_t>(request.kind)==107) {
                    if(!rules.hibernate) throw CodecError("richonline_sleep_protection_resources_required");
                    RichonlineProtectionInventory protection_inventory{static_cast<std::uint8_t>(target),static_cast<std::uint8_t>(target),{},std::nullopt,false};
                    if(static_cast<std::uint8_t>(target)==init.local_slot) protection_inventory.main=inventory;
                    const auto protection=resolve_richonline_sleep_protection(rules.cards->map_name(),*rules.hibernate->resources,protection_inventory,status[static_cast<std::uint8_t>(target)]);
                    if(protection.consumed || status[static_cast<std::uint8_t>(target)].protected_from_status) card.after.status=status[static_cast<std::uint8_t>(target)];
                    if(static_cast<std::uint8_t>(target)==init.local_slot) inventory=protection.after.main;
                }
                script_consumption->remaining_inventory=inventory;
                auto clock=rules.npcs ? std::optional{rules.npcs->prepare_status_change(static_cast<std::uint8_t>(target),status[static_cast<std::uint8_t>(target)],card.after.status)} : std::nullopt;
                auto movement=card.movement_steps ? std::optional{prepare_move(*card.movement_steps)} : std::nullopt;
                script_motion=ScriptMotion{std::move(card),static_cast<std::uint8_t>(target),std::move(clock),std::move(movement)};
                auto movement_packets=LuaValue::array(); if(script_motion->movement) for(const auto& packet:script_motion->movement->messages) movement_packets.push_back(lua_bytes(View(packet)));
                auto recovery=LuaValue::array(); if(script_motion->card.recovery) recovery.push_back(lua_bytes(View(*script_motion->card.recovery)));
                return LuaValue{{"response",lua_bytes(View(script_motion->card.response))},{"movement",std::move(movement_packets)},{"recovery",std::move(recovery)},{"continuation",script_motion->card.continuation==RichonlineMotionCardContinuation::await_same_position17 ? "stationary" : "resume"}};
            }},
            {"inventory.consumed_snapshot",[&](const LuaValue&) {
                if(called || database_called || !script_consumption || script_shuffle || script_inventory_cleared || script_motion)
                    throw CodecError("lua_inventory_snapshot_out_of_scope");
                auto stacks=LuaValue::array();
                for(std::uint8_t slot=0;slot<script_consumption->remaining_inventory.size();++slot) {
                    const auto& entry=script_consumption->remaining_inventory[slot];
                    if(entry.card_id==-1 && entry.count==0) continue;
                    stacks.push_back({{"slot",slot},{"card",entry.card_id},{"count",entry.count}});
                }
                return stacks;
            }},
            {"inventory.prepare_reorder",[&](const LuaValue& args) {
                if(called || database_called || !script_consumption || script_shuffle || script_inventory_cleared || script_motion ||
                    script_consumption->card_id!=1125 || plain.size()!=6 || read_le(plain.first(2))!=152)
                    throw CodecError("lua_inventory_reorder_out_of_scope");
                const auto& slots=args.at("slots");
                if(!slots.is_array() || slots.size()>8) throw CodecError("lua_inventory_reorder_slots_invalid");
                std::vector<std::uint8_t> order;
                order.reserve(slots.size());
                for(const auto& slot:slots) {
                    if(!slot.is_number_integer() || slot<0 || slot>=8)
                        throw CodecError("lua_inventory_reorder_slot_invalid");
                    order.push_back(slot.get<std::uint8_t>());
                }
                auto prepared=rules.cards->prepare_shuffle_order(script_consumption->slot,actor,order);
                if(prepared.source_inventory!=script_consumption->source_inventory)
                    throw CodecError("lua_inventory_reorder_source_changed");
                script_consumption->remaining_inventory=prepared.remaining_inventory;
                script_shuffle=std::move(prepared);
                return LuaValue{};
            }},
            {"inventory.prepare_clear",[&](const LuaValue& args) {
                if(called || database_called || !script_consumption || script_inventory_cleared || script_shuffle)
                    throw CodecError("lua_inventory_clear_out_of_scope");
                const auto& cards=args.at("cards");
                if(!cards.is_array() || cards.size()>8) throw CodecError("lua_inventory_clear_ids_invalid");
                std::vector<std::int16_t> ids;
                ids.reserve(cards.size());
                for(const auto& value:cards) {
                    if(!value.is_number_integer() || value<1 || value>32767)
                        throw CodecError("lua_inventory_clear_id_invalid");
                    ids.push_back(value.get<std::int16_t>());
                }
                for(auto& slot:script_consumption->remaining_inventory)
                    if(std::ranges::find(ids,slot.card_id)!=ids.end()) slot={};
                script_inventory_cleared=true;
                return LuaValue{};
            }},
            {"property.prepare",[&](const LuaValue& args) {
                if(called || database_called || !script_consumption || script_property || script_street || !rules.property)
                    throw CodecError("lua_property_prepare_out_of_scope");
                const auto integer=[&](const char* key,std::int64_t low,std::int64_t high) {
                    const auto& value=args.at(key);
                    if(!value.is_number_integer() || value<low || value>high)
                        throw CodecError("lua_property_argument_invalid");
                    return value.get<std::int64_t>();
                };
                const auto operation=args.at("operation").get<std::string>();
                const auto source=topology.cell(init.participants[actor].position).property_ref;
                LuaValue result=LuaValue::object();
                if(operation=="seal" || operation=="price_rise") {
                    if(status[actor].frozen) throw CodecError("richonline_street_card_request_invalid");
                    script_street=rules.property->prepare_street_card(source,operation=="seal" ?
                        RichonlineBossProperty::StreetEffect::seal : RichonlineBossProperty::StreetEffect::price_rise);
                    result["affected"]=script_street->affected_properties();
                } else if(operation=="convert" || operation=="convert_classic") {
                    const auto ref=static_cast<std::int16_t>(integer("property",0,32767));
                    const auto kind=static_cast<std::int8_t>(integer("kind",2,20));
                    script_property=operation=="convert" ? rules.property->prepare_conversion_card(ref,kind,actor) :
                        rules.property->prepare_classic_conversion_card(ref,kind);
                } else if(operation=="house") {
                    script_property=rules.property->prepare_house_card(static_cast<std::int16_t>(integer("position",0,32767)),actor);
                } else if(operation=="swap") {
                    script_property=rules.property->prepare_swap_card(source,
                        static_cast<std::int16_t>(integer("property",0,32767)),args.at("buildings").get<bool>());
                } else if(operation=="grow") {
                    script_property=rules.property->prepare_growth_card(source,
                        args.at("own_only").get<bool>() ? std::optional{actor} : std::nullopt,
                        static_cast<int>(integer("levels",-5,5)));
                } else if(operation=="destroy") {
                    const auto ref=args.at("current").get<bool>() ? source :
                        static_cast<std::int16_t>(integer("property",0,32767));
                    script_property=rules.property->prepare_destruction_card(ref,static_cast<std::uint8_t>(integer("levels",1,5)));
                } else if(operation=="purchase") {
                    if(!rules.ledger || !rules.human_purchase_half_price)
                        throw CodecError("richonline_purchase_card_authority_required");
                    script_property=rules.property->prepare_purchase_card(source,actor);
                    const auto cost=rules.property->purchase_price(source,actor);
                    if(!cost || *cost>0x7fffffffU) throw CodecError("richonline_purchase_card_price_invalid");
                    result["price"]=*cost;
                } else throw CodecError("lua_property_operation_invalid");
                return result;
            }},
            {"funds.prepare",[&](const LuaValue& args) {
                if(called || !script_consumption || !rules.ledger)
                    throw CodecError("lua_funds_prepare_out_of_scope");
                if(!args.at("actor").is_number_integer()) throw CodecError("lua_funds_actor_invalid");
                const auto requested_actor=args.at("actor").get<std::int64_t>();
                if(requested_actor<0 || requested_actor>=static_cast<std::int64_t>(active.size()) || !active[static_cast<std::size_t>(requested_actor)])
                    throw CodecError("lua_funds_actor_invalid");
                const auto target=static_cast<std::uint8_t>(requested_actor);
                if(std::ranges::any_of(script_funds,[&](const auto& entry){return entry.actor==target;}))
                    throw CodecError("lua_funds_actor_already_prepared");
                const auto before=rules.ledger->snapshot(target);auto after=before.funds;
                const auto adjust=[](std::uint32_t value,std::int64_t delta) {
                    if(delta < -static_cast<std::int64_t>(value) || delta > 0x7fffffffLL-static_cast<std::int64_t>(value))
                        throw CodecError("lua_funds_out_of_range");
                    return static_cast<std::uint32_t>(static_cast<std::int64_t>(value)+delta);
                };
                const auto delta=[&](const char* key) {
                    if(!args.contains(key)) return std::int64_t{0};
                    if(!args.at(key).is_number_integer() || args.at(key)<-0x7fffffffLL || args.at(key)>0x7fffffffLL)
                        throw CodecError("lua_funds_delta_invalid");
                    return args.at(key).get<std::int64_t>();
                };
                after.cash=adjust(after.cash,delta("cash"));
                after.tickets=adjust(after.tickets,delta("tickets"));
                if(args.contains("deposit")) {
                    if(!after.deposit) throw CodecError("lua_funds_deposit_unknown");
                    *after.deposit=adjust(*after.deposit,delta("deposit"));
                }
                script_funds.push_back({target,before,after});
                return LuaValue{{"cash",after.cash},{"tickets",after.tickets}};
            }},
            {"relations.break",[&](const LuaValue& args) {
                if(called || database_called || !script_consumption || script_break_alliance || script_set_alliance || script_clear_relations)
                    throw CodecError("lua_relation_prepare_out_of_scope");
                const auto& value=args.at("target");
                if(!value.is_number_integer() || value<0 || value>=active.size())
                    throw CodecError("lua_relation_target_invalid");
                const auto target=value.get<std::uint8_t>();
                if(target==actor || !active[target]) throw CodecError("lua_relation_target_invalid");
                script_break_alliance=target;return LuaValue{};
            }},
            {"relations.rules",[&](const LuaValue&) {
                return LuaValue{{"alliance_days",rules.alliance_days}};
            }},
            {"relations.prepare",[&](const LuaValue& args) {
                if(called || database_called || !script_consumption || script_break_alliance || script_set_alliance || script_clear_relations)
                    throw CodecError("lua_relation_prepare_out_of_scope");
                const auto& value=args.at("target");
                const auto& duration=args.at("days");
                if(!value.is_number_integer() || value<0 || value>=active.size() ||
                    !duration.is_number_integer() || duration<1 || duration>127)
                    throw CodecError("lua_relation_argument_invalid");
                const auto target=value.get<std::uint8_t>();
                if(target==actor || !active[target]) throw CodecError("lua_relation_target_invalid");
                script_set_alliance=std::pair{target,duration.get<std::uint8_t>()};
                return LuaValue{};
            }},
            {"relations.clear_actor",[&](const LuaValue& args) {
                if(called || database_called || !script_consumption || script_break_alliance || script_set_alliance || script_clear_relations)
                    throw CodecError("lua_relation_prepare_out_of_scope");
                const auto& value=args.at("target");
                if(!value.is_number_integer() || value<0 || value>=active.size())
                    throw CodecError("lua_relation_target_invalid");
                const auto target=value.get<std::uint8_t>();
                if(!active[target]) throw CodecError("lua_relation_target_invalid");
                script_clear_relations=target;
                return LuaValue{};
            }},
            {"npc.summon_candidates",[&](const LuaValue& args) {
                require_local_controls();
                if(called || database_called || !script_consumption || script_consumption->card_id!=1047 ||
                    script_summon_snapshot || !rules.npcs || !rules.raw_authority || !rules.npc_summon_candidates ||
                    npc_landing || npc_pending_counter || phase!=Phase::roll || actor!=init.local_slot ||
                    plain.size()!=8 || read_le(plain.first(2))!=112)
                    throw CodecError("lua_summon_snapshot_out_of_scope");
                const auto& value=args.at("target");
                if(!value.is_number_integer() || value<0 || value>=active.size() || value!=plain[6])
                    throw CodecError("lua_summon_target_invalid");
                const auto target=value.get<std::uint8_t>();
                if(!active[target] || !raw_available(target)) throw CodecError("lua_summon_target_unavailable");
                const auto allowed=rules.npc_summon_candidates(landing_context(init.participants[actor].position));
                for(const auto position:allowed)
                    if(!topology.cell(position).walkable) throw CodecError("richonline_boss_summon_candidate_cell_invalid");
                auto candidates=rules.npcs->summon_candidates(allowed);
                const auto position=init.participants[target].position;
                const auto width=static_cast<std::int64_t>(topology.width());
                auto result=LuaValue::array();
                for(const auto& candidate:candidates) {
                    const auto dx=candidate.position%width-position%width,dy=candidate.position/width-position/width;
                    result.push_back({{"position",candidate.position},{"npc",candidate.id},{"distance_squared",dx*dx+dy*dy}});
                }
                script_summon_snapshot=ScriptSummonSnapshot{actor,target,active_counter,turn_sequence,
                    init.participants[actor].position,position,status[actor],status[target],
                    rules.raw_authority->actor(target),std::move(candidates)};
                return result;
            }},
            {"npc.prepare_summon",[&](const LuaValue& args) {
                if(called || database_called || !script_consumption || !script_summon_snapshot || script_summon)
                    throw CodecError("lua_summon_prepare_out_of_scope");
                const auto& position=args.at("position");const auto& snapshot=*script_summon_snapshot;
                if(!position.is_number_integer() || position<0 || position>32767)
                    throw CodecError("lua_summon_position_invalid");
                const auto chosen=position.get<std::int16_t>();
                if(std::ranges::none_of(snapshot.candidates,[&](const auto& candidate){return candidate.position==chosen;}))
                    throw CodecError("lua_summon_position_not_candidate");
                const std::array selected{chosen};
                auto prepared=rules.npcs->prepare_deity_card(plain,landing_context(init.participants[actor].position),
                    active_counter,status[snapshot.target],raw_available(snapshot.target),selected,
                    [](std::size_t){return std::size_t{0};});
                const auto& packets=prepared.result().messages;
                auto effects=LuaValue::array();
                for(std::size_t i=1;i<packets.size();++i) effects.push_back(lua_bytes(View(packets[i])));
                script_summon=std::move(prepared);
                return effects;
            }},
            {"npc.prepare_attach",[&](const LuaValue& args) {
                if(called || database_called || !script_consumption || script_status || script_god_card ||
                    !rules.npcs || npc_landing || npc_pending_counter || plain.size()!=6)
                    throw CodecError("lua_npc_attach_out_of_scope");
                const auto& value=args.at("npc");
                if(!value.is_number_integer() || (value!=0 && value!=3))
                    throw CodecError("lua_npc_attach_kind_invalid");
                const auto npc=value.get<std::int8_t>();
                if(read_le(plain.first(2))!=(npc==0 ? 130U : 131U) || script_consumption->card_id!=(npc==0 ? 1069 : 1070))
                    throw CodecError("lua_npc_attach_card_mismatch");
                auto clock=rules.npcs->prepare_card_attachment(landing_context(init.participants[actor].position),
                    npc,active_counter,status[actor]);
                Bytes confirmation;append_le(confirmation,npc==0 ? 0x40d2 : 0x40d3,2);
                append_le(confirmation,init.game_server_id,2);confirmation.push_back(plain[4]);confirmation.push_back(0);
                script_status=ScriptStatus{actor,status[actor],clock.after(),std::move(clock)};
                script_god_card=ScriptGodCard{actor,npc,active_counter,turn_sequence,init.participants[actor].position,
                    script_consumption->remaining_inventory,std::move(confirmation),{}, {}};
                return LuaValue{};
            }},
            {"inventory.prepare_fortune",[&](const LuaValue&) {
                if(called || database_called || !script_god_card || script_god_card->npc!=3 || script_god_card->reward ||
                    script_consumption->remaining_inventory!=script_god_card->consumed_inventory)
                    throw CodecError("lua_fortune_reward_out_of_scope");
                auto reward=rules.npcs->prepare_fortune_rewards(script_consumption->remaining_inventory);
                auto chosen=LuaValue::array();for(const auto card:reward.cards) chosen.push_back(card);
                script_consumption->remaining_inventory=reward.inventory;
                script_god_card->reward=std::move(reward);
                return chosen;
            }},
            {"npc.prepare_detach",[&](const LuaValue& args) {
                if(called || database_called || !script_consumption || script_status || script_dismiss ||
                    !rules.npcs || !rules.raw_authority || npc_landing || script_consumption->card_id!=1048 ||
                    plain.size()!=8 || read_le(plain.first(2))!=113)
                    throw CodecError("lua_npc_detach_out_of_scope");
                const auto& value=args.at("target");
                if(!value.is_number_integer() || value<0 || value>=active.size())
                    throw CodecError("lua_npc_detach_target_invalid");
                const auto target=value.get<std::uint8_t>();
                if(target!=plain[6] || !active[target] || !raw_available(target))
                    throw CodecError("lua_npc_detach_target_unavailable");
                auto clock=rules.npcs->prepare_card_detachment(landing_context(init.participants[actor].position),
                    target,status[target]);
                Bytes response;append_le(response,0x40c1,2);append_le(response,init.game_server_id,2);
                response.push_back(plain[4]);response.push_back(0);response.push_back(target);
                script_status=ScriptStatus{target,status[target],clock.after(),std::move(clock)};
                script_dismiss=ScriptDismiss{actor,target,active_counter,turn_sequence,status[actor],
                    rules.raw_authority->actor(target),std::move(response)};
                return LuaValue{};
            }},
            {"status.prepare_clear",[&](const LuaValue& args) {
                if(called || database_called || !script_consumption || script_status)
                    throw CodecError("lua_status_prepare_out_of_scope");
                const auto& value=args.at("target");
                const auto& fields=args.at("fields");
                if(!value.is_number_integer() || value<0 || value>=active.size() ||
                    !fields.is_array() || fields.empty() || fields.size()>8)
                    throw CodecError("lua_status_arguments_invalid");
                const auto target=value.get<std::uint8_t>();
                if(!active[target]) throw CodecError("lua_status_target_inactive");
                const auto before=status[target];auto after=before;
                std::vector<std::string> seen;
                seen.reserve(fields.size());
                for(const auto& entry:fields) {
                    if(!entry.is_string()) throw CodecError("lua_status_field_invalid");
                    const auto field=entry.get<std::string>();
                    if(std::ranges::find(seen,field)!=seen.end()) throw CodecError("lua_status_field_duplicate");
                    seen.push_back(field);
                    if(field=="possession") richonline_detach_possession(after);
                    else if(field=="timed_bomb") {after.timed_bomb.reset();after.timed_bomb_owner.reset();}
                    else if(field=="sleepwalking") after.sleepwalking=0;
                    else if(field=="turtle") after.turtle=0;
                    else if(field=="stay") after.stay=0;
                    else if(field=="one_step") after.one_step=0;
                    else if(field=="six_steps") after.six_steps=0;
                    else if(field=="frozen") after.frozen=0;
                    else throw CodecError("lua_status_field_unsupported");
                }
                std::optional<RichonlineNpcSession::PreparedStatusChange> clock;
                if(rules.npcs && after!=before) clock=rules.npcs->prepare_status_change(target,before,after);
                script_status=ScriptStatus{target,before,after,std::move(clock)};
                return LuaValue{};
            }},
            {"map.info",[&](const LuaValue&) {
                return LuaValue{{"width",topology.width()},{"height",topology.height()},{"cells",topology.cells().size()}};
            }},
            {"route.preview_open_road",[&](const LuaValue&) {
                if(called || database_called || !script_consumption || !rules.ground ||
                    std::exchange(script_route_previewed,true))
                    throw CodecError("lua_open_road_preview_out_of_scope");
                // 沿用原有十步寻路参数：不走传送、银行可穿过；这里只读棋盘并消耗本局随机数。
                const auto route=build_richonline_route(topology,
                    {init.participants[actor].position,init.participants[actor].direction,10,{},false,true},rules.random);
                auto directions=LuaValue::array(),landings=LuaValue::array();
                for(const auto direction:route.directions) directions.push_back(direction);
                for(const auto position:route.landings) landings.push_back(position);
                return LuaValue{{"directions",std::move(directions)},{"landings",std::move(landings)}};
            }},
            {"actor.relocation_snapshot",[&](const LuaValue&) {
                if(!script_consumption) throw CodecError("lua_actor_relocation_out_of_scope");
                auto result=LuaValue::array();
                for(std::uint8_t slot=0;slot<active.size();++slot)
                    result.push_back({{"slot",slot},{"active",active[slot]},
                        {"position",init.participants[slot].position},{"frozen",status[slot].frozen!=0},
                        {"protected_from_status",status[slot].protected_from_status},
                        {"raw_available",raw_available(slot)}});
                return result;
            }},
            {"actor.jail_rules",[&](const LuaValue&) {
                return LuaValue{{"available",topology.jail_positions().has_value()},{"days",rules.jail_days}};
            }},
            {"actor.prepare_jail",[&](const LuaValue& args) {
                if(called || database_called || !script_consumption || script_jail || !rules.raw_authority ||
                    script_consumption->card_id!=1054 || plain.size()!=8 || read_le(plain.first(2))!=117)
                    throw CodecError("lua_jail_prepare_out_of_scope");
                const auto& value=args.at("target");
                const auto& apply=args.at("apply");
                if(!value.is_number_integer() || value<0 || value>=active.size() || !apply.is_boolean())
                    throw CodecError("lua_jail_arguments_invalid");
                const auto target=value.get<std::uint8_t>();
                const auto applied=apply.get<bool>();
                const auto jail=topology.jail_positions();
                if(target!=plain[6] || target==actor || !active[target] || !raw_available(target) || status[target].frozen ||
                    !jail || rules.jail_days>127 || applied==status[target].protected_from_status)
                    throw CodecError("lua_jail_target_unavailable");
                auto raw=rules.raw_authority->prepare_jail_entry(target,static_cast<std::int8_t>(rules.jail_days));
                const auto before=status[target];auto after=before;
                if(applied) after.stay=0; // 客户端入狱动画清除1496，保留附身及其倒计时。
                auto clock=rules.npcs && after!=before ?
                    std::optional{rules.npcs->prepare_status_change(target,before,after)} : std::nullopt;
                Bytes response;append_le(response,0x40c5,2);append_le(response,init.game_server_id,2);
                response.push_back(plain[4]);response.push_back(0);response.push_back(target);response.push_back(0);
                script_jail=ScriptJail{actor,target,active_counter,turn_sequence,init.participants[target].position,
                    applied ? (*jail)[0] : init.participants[target].position,before,after,std::move(raw),std::move(clock),
                    applied,std::move(response)};
                return LuaValue{};
            }},
            {"actor.prepare_positions",[&](const LuaValue& args) {
                if(called || database_called || !script_consumption || script_positions_prepared)
                    throw CodecError("lua_actor_position_prepare_out_of_scope");
                const auto& positions=args.at("positions");
                if(!positions.is_array() || positions.empty() || positions.size()>active.size())
                    throw CodecError("lua_actor_positions_invalid");
                std::vector<ScriptPosition> prepared;
                prepared.reserve(positions.size());
                for(const auto& entry:positions) {
                    const auto& slot_value=entry.at("actor");
                    const auto& position_value=entry.at("position");
                    if(!slot_value.is_number_integer() || slot_value<0 || slot_value>=active.size() ||
                        !position_value.is_number_integer() || position_value<0 || position_value>32767)
                        throw CodecError("lua_actor_position_invalid");
                    const auto slot=slot_value.get<std::uint8_t>();
                    const auto position=position_value.get<std::int16_t>();
                    if(!active[slot] || static_cast<std::size_t>(position)>=topology.cells().size() ||
                        !topology.cell(position).walkable ||
                        std::ranges::any_of(prepared,[&](const auto& previous){return previous.slot==slot;}))
                        throw CodecError("lua_actor_position_unavailable");
                    prepared.push_back({slot,init.participants[slot].position,position});
                }
                script_positions=std::move(prepared);
                script_positions_prepared=true;
                return LuaValue{};
            }},
            {"research.traps",[&](const LuaValue& args) {
                const auto kind=args.at("kind").get<std::string>();
                const auto* traps=kind=="ice" ? rules.ice_traps.get() :
                    kind=="fire" && rules.fire_traps ? &rules.fire_traps->traps : nullptr;
                if(!traps || !rules.ground || !rules.ground_card_visible)
                    throw CodecError("richonline_boss_research_card_authority_required");
                return LuaValue{{"freeze_timer",traps->freeze_timer},{"fire_radius",traps->fire_radius},{"fire_rounds",traps->fire_rounds}};
            }},
            {"map.cell",[&](const LuaValue& args) {
                const auto& value=args.at("position");
                if(!value.is_number_integer() || value<0 || value>=topology.cells().size())
                    throw CodecError("lua_map_position_invalid");
                const auto position=value.get<std::int16_t>();
                const auto& cell=topology.cell(position);
                const auto occupied=std::ranges::any_of(init.participants,[&](const auto& entry){return entry.position==position;});
                bool active_occupied=false;
                for(std::size_t slot=0;slot<active.size();++slot)
                    if(active[slot] && init.participants[slot].position==position) active_occupied=true;
                return LuaValue{{"position",position},{"walkable",cell.walkable},{"static_type",cell.static_type},
                    {"property",cell.property_ref},{"actor_occupied",occupied},{"placement_occupied",placement_occupied(position)},
                    {"active_actor_occupied",active_occupied},{"ground_occupied",rules.ground && ground_snapshot().objects.contains(position)},
                    {"ground_visible",rules.ground_card_visible && rules.ground_card_visible(actor,init.participants[actor].position,position)}};
            }},
            {"ground.prepare",[&](const LuaValue& args) {
                return prepare_ground(LuaValue::array({args}));
            }},
            {"ground.prepare_batch",[&](const LuaValue& args) {
                return prepare_ground(args.at("objects"));
            }},
            {"ground.snapshot",[&](const LuaValue&) {
                auto objects=LuaValue::array();
                for(const auto& [position,object]:ground_snapshot().objects)
                    objects.push_back({{"position",position},{"npc",object.npc},{"byte7",object.byte7},{"byte8",object.byte8}});
                return objects;
            }},
            {"ground.prepare_remove",[&](const LuaValue& args) {
                if(called || database_called || !script_consumption || script_ground || !rules.ground || status[actor].frozen)
                    throw CodecError("lua_ground_prepare_out_of_scope");
                const auto& positions=args.at("positions");
                const auto& before=ground_snapshot();
                if(!positions.is_array() || positions.size()>before.objects.size())
                    throw CodecError("lua_ground_removals_invalid");
                auto after=before.objects;
                for(const auto& position:positions) {
                    if(position.is_number_integer() && position>=0 && position<=32767) {
                        const auto found=after.find(position.get<std::int16_t>());
                        if(found!=after.end() && found->second.npc==32)
                            throw CodecError("lua_ground_boss_chest_protected");
                    }
                    if(!position.is_number_integer() || position<0 || position>32767 ||
                        after.erase(position.get<std::int16_t>())!=1)
                        throw CodecError("lua_ground_removal_missing_or_duplicate");
                }
                script_ground=rules.ground->prepare(before,after);
                return LuaValue{};
            }},
            {"game.snapshot",[&](const LuaValue&) {
                auto actors=LuaValue::array();
                for(std::uint8_t slot=0;slot<active.size();++slot) {
                    LuaValue value{{"slot",slot},{"active",active[slot]},
                        {"position",init.participants[slot].position},{"possession",status[slot].possession}};
                    if(rules.ledger) {const auto funds=rules.ledger->snapshot(slot);
                        value["cash"]=funds.funds.cash;value["tickets"]=funds.funds.tickets;value["revision"]=funds.revision;
                        value["deposit"]=funds.funds.deposit ? LuaValue(*funds.funds.deposit) : LuaValue{};}
                    actors.push_back(std::move(value));
                }
                auto inventory=LuaValue::array();
                if(rules.cards) for(const auto& slot:rules.cards->inventory())
                    inventory.push_back({{"card",slot.card_id},{"count",slot.count}});
                return LuaValue{{"actors",actors},{"inventory",inventory},{"actor",actor},
                    {"calendar",active_counter},{"round",complete_rounds},{"game_id",init.game_server_id},
                    {"can_act",active[actor] && !richonline_landing_controlled(status[actor])}};
            }},
            {"random",[&](const LuaValue& args) {
                const auto upper=args.at("upper").get<std::int64_t>();
                if(upper<1||upper>0x7fffffff) throw CodecError("lua_random_bound_invalid");
                return LuaValue(rules.random(static_cast<std::size_t>(upper))+1);
            }},
            {"log",[&](const LuaValue& args) {if(rules.log) rules.log("lua_game "+args.dump());return LuaValue{};}}
        };
        if(rules.script_database) api.emplace("db.batch",[&](const LuaValue& request) {
            if(called || script_consumption) throw CodecError("lua_cannot_mix_database_and_game_transaction");
            database_called=true;return rules.script_database(request);
        });
        LuaValue result;
        std::vector<Bytes> messages;
        try {
            result=rules.script->call("game.action",{{"payload",lua_bytes(plain)},
                {"opcode",plain.size()>=2?read_le(plain.first(2)):0},{"map",rules.script_map},
                {"actor",actor},{"calendar",active_counter},{"game_id",init.game_server_id}},api);
            if(!result.is_array()||result.size()>1024) throw CodecError("lua_game_response_invalid");
            for(const auto& packet:result) messages.push_back(lua_bytes(packet));
            if(script_ground && (script_positions_prepared || script_motion || script_movement))
                throw CodecError("lua_ground_cannot_mix_movement");
            if(script_summon_snapshot) {
                if(!script_summon || script_attack || script_hibernate_snapshot || script_motion || script_movement ||
                    script_shuffle || script_jail || script_dismiss || script_god_card || script_property || script_street ||
                    script_ground || script_status || script_break_alliance || script_set_alliance || script_clear_relations ||
                    script_positions_prepared || script_inventory_cleared || !script_funds.empty())
                    throw CodecError("lua_summon_cannot_mix_mutations");
                if(messages!=script_summon->result().messages)
                    throw CodecError("lua_summon_response_invalid");
                const auto& result=script_summon->result();
                if(!result.summoned || result.continuation!=RichonlineNpcContinuation::restore_action ||
                    (result.wait!=RichonlineNpcWait::none && result.wait!=RichonlineNpcWait::roulette34))
                    throw CodecError("lua_summon_continuation_invalid");
                const auto& snapshot=*script_summon_snapshot;
                const auto width=static_cast<std::int64_t>(topology.width());
                const auto position=result.summoned->position;
                const auto dx=position%width-snapshot.target_position%width,dy=position/width-snapshot.target_position/width;
                script_summon_log="richonline_summon_selected actor="+std::to_string(actor)+
                    " target="+std::to_string(snapshot.target)+" target_position="+std::to_string(snapshot.target_position)+
                    " npc="+std::to_string(result.summoned->id)+" npc_position="+std::to_string(position)+
                    " distance_squared="+std::to_string(dx*dx+dy*dy)+
                    " policy=nearest-target-grid-distance-then-position-v1 lua_card=1047";
                // 所有时钟回调在提交前完成；召来糊涂神后使用受控掷骰超时，钱神等待34。
                const auto now=rules.now();
                if(script_summon->result().wait==RichonlineNpcWait::roulette34)
                    script_summon_deadline=now+rules.npc_roulette_timeout;
                const auto& next=script_summon_snapshot->target==actor ? script_summon->after_status() : status[actor];
                if(next.possession==7 || next.sleepwalking)
                    script_summon_roll_deadline=now+rules.controlled_roll_timeout;
            }
            if(script_attack) {
                if(script_hibernate_snapshot || script_motion || script_movement || script_shuffle || script_jail ||
                    script_dismiss || script_god_card || script_property || script_street || script_ground || script_status ||
                    script_break_alliance || script_set_alliance || script_clear_relations || script_positions_prepared ||
                    script_inventory_cleared || !script_funds.empty() ||
                    script_consumption->remaining_inventory!=script_attack->consumed_inventory)
                    throw CodecError("lua_attack_cannot_mix_mutations");
                if(messages!=script_attack->prepared.packets()) throw CodecError("lua_attack_response_invalid");
            }
            if(script_hibernate_snapshot) {
                if(!script_hibernate || script_motion || script_movement || script_shuffle || script_jail ||
                    script_dismiss || script_god_card || script_property || script_street || script_ground || script_status ||
                    script_break_alliance || script_set_alliance || script_clear_relations || script_positions_prepared ||
                    script_inventory_cleared || !script_funds.empty())
                    throw CodecError("lua_hibernate_cannot_mix_mutations");
                if(messages.size()!=1 || messages.front()!=script_hibernate->plan.response40f4 ||
                    script_consumption->remaining_inventory!=script_hibernate->plan.after.actors[actor].inventory.main)
                    throw CodecError("lua_hibernate_response_invalid");
                if(!hibernate_matches(*script_hibernate)) throw CodecError("lua_hibernate_snapshot_changed");
            }
            if(script_god_card) {
                // 附身确认和福神两张奖励组成一个完整事务；不能漏发、换序或混入其他修改。
                if(script_motion || script_movement || script_shuffle || script_jail || script_dismiss || script_property ||
                    script_street || script_ground || script_break_alliance || script_set_alliance || script_clear_relations ||
                    script_positions_prepared || script_inventory_cleared || !script_funds.empty())
                    throw CodecError("lua_god_card_cannot_mix_mutations");
                const auto& god=*script_god_card;
                if((god.npc==3)!=god.reward.has_value() || messages.size()!=(god.npc==3 ? 2U : 1U) ||
                    messages.front()!=god.confirmation ||
                    (god.reward && messages[1]!=god.reward->response4023) ||
                    script_consumption->remaining_inventory!=(god.reward ? god.reward->inventory : god.consumed_inventory))
                    throw CodecError("lua_god_card_response_invalid");
                // 时钟读取也在提交前完成；提交后只切换已经准备好的转盘等待状态。
                if(god.npc==0) script_god_card->deadline=rules.now()+rules.npc_roulette_timeout;
            }
            if(script_dismiss) {
                // 送神仅提交附身状态/时钟及扣卡；七字节40C1不带请求中的未使用字节。
                if(script_motion || script_movement || script_shuffle || script_jail || script_property || script_street ||
                    script_ground || script_break_alliance || script_set_alliance || script_clear_relations ||
                    script_positions_prepared || script_inventory_cleared || !script_funds.empty())
                    throw CodecError("lua_npc_detach_cannot_mix_mutations");
                if(messages.size()!=1 || messages.front()!=script_dismiss->response)
                    throw CodecError("lua_npc_detach_response_invalid");
            }
            if(script_jail) {
                // 陷害只允许入狱与解除施放者/目标同盟，不允许再混入其他状态或库存业务。
                if(script_motion || script_movement || script_shuffle || script_property || script_street || script_ground ||
                    script_status || script_set_alliance || script_clear_relations || script_positions_prepared ||
                    script_inventory_cleared || !script_funds.empty() || script_break_alliance!=script_jail->target)
                    throw CodecError("lua_jail_cannot_mix_mutations");
                if(messages.size()!=1 || messages.front()!=script_jail->response)
                    throw CodecError("lua_jail_response_invalid");
            }
            if(script_shuffle) {
                // 洗牌回包必须精确描述准备的插入顺序；禁止随后混入其他业务或更改准备库存。
                if(script_motion || script_movement || script_property || script_street || script_ground || script_status ||
                    script_break_alliance || script_set_alliance || script_clear_relations || script_positions_prepared ||
                    script_inventory_cleared || !script_funds.empty() ||
                    script_consumption->remaining_inventory!=script_shuffle->remaining_inventory)
                    throw CodecError("lua_inventory_reorder_cannot_mix_mutations");
                if(messages.size()!=1 || messages.front()!=script_shuffle->confirmation40e8)
                    throw CodecError("lua_inventory_reorder_response_invalid");
            }
            if(script_movement) {
                // 路线来自动作开始时的状态；禁止在同一脚本中再改变它依赖的状态。
                if(script_motion || script_property || script_street || script_ground || script_status ||
                    script_break_alliance || script_set_alliance || script_clear_relations ||
                    script_positions_prepared || script_inventory_cleared || !script_funds.empty())
                    throw CodecError("lua_route_cannot_mix_mutations");
                const auto& route_packets=script_movement->move.messages;
                if(messages.size()!=route_packets.size()+1 ||
                    !std::equal(route_packets.begin(),route_packets.end(),messages.begin()+1))
                    throw CodecError("lua_route_response_sequence_invalid");
            }
            if(script_consumption) {
                if(messages.empty()) throw CodecError("lua_card_response_required");
                for(const auto& packet:messages)
                    if(packet.size()<4 || read_le(View(packet).subspan(2,2))!=init.game_server_id)
                        throw CodecError("lua_card_response_game_mismatch");
            }
        } catch(const std::exception& error) {
            // 新 Lua 卡牌的计划尚未提交，可安全恢复操作；原生接口执行后禁止自动重试。
            if(!called && !database_called && plain.size()>=2) {
                const auto opcode=read_le(plain.first(2));
                if(opcode>=96 && opcode<=174) {
                    if(rules.log) rules.log(std::string("lua_card_refused reason=")+error.what());
                    return {encode_richonline_dice_recovery400b(init.game_server_id)};
                }
            }
            throw;
        }
        if(script_summon) {
            const auto& snapshot=*script_summon_snapshot;
            if(phase!=Phase::roll || actor!=snapshot.source || active_counter!=snapshot.calendar || turn_sequence!=snapshot.turn ||
                npc_landing || npc_pending_counter || !active[actor] || !active[snapshot.target] ||
                init.participants[actor].position!=snapshot.source_position ||
                init.participants[snapshot.target].position!=snapshot.target_position || status[actor]!=snapshot.source_status ||
                status[snapshot.target]!=snapshot.target_status || rules.raw_authority->actor(snapshot.target)!=snapshot.target_raw ||
                rules.cards->inventory()!=script_consumption->source_inventory)
                throw CodecError("lua_summon_snapshot_changed");
            auto result=rules.npcs->commit_deity_card(*script_summon,status[snapshot.target]);
            if(result.wait==RichonlineNpcWait::roulette34) {
                npc_pending_counter=active_counter;npc_retired_counter.reset();
                npc_deadline=script_summon_deadline;phase=Phase::npc;
            } else {
                npc_deadline.reset();phase=Phase::roll;controlled_roll_deadline=script_summon_roll_deadline;
            }
            if(rules.log) rules.log(script_summon_log);
            return std::move(result.messages);
        }
        if(script_attack) {
            if(phase!=Phase::roll || actor!=script_attack->actor || active_counter!=script_attack->calendar ||
                turn_sequence!=script_attack->turn)
                throw CodecError("lua_attack_turn_changed");
            auto refs=combat_refs();
            if(script_poison_raw) for(std::uint8_t slot=0;slot<active.size();++slot)
                if(rules.poison_raw_actor(slot)!=(*script_poison_raw)[slot])
                    throw CodecError("lua_poison_raw_state_changed");
            auto attack=script_poison_raw ?
                rules.combat->commit_poison_card(refs,script_attack->prepared,poison_use_count,relations1472) :
                rules.combat->commit_human_attack(refs,script_attack->prepared,rules.log);
            if(rules.log) rules.log("lua_card_committed card="+std::to_string(script_consumption->card_id)+
                " slot="+std::to_string(script_consumption->slot)+" combat=1");
            // 核心已一起提交扣卡、保护卡、资金和地产；不能再走通用库存提交覆盖战斗结果。
            if(!attack.bankrupt_actors.empty())
                return terminal(std::move(attack.packets),std::move(attack.bankrupt_actors),
                    script_poison_raw ? RichonlineTerminalReason::poison_card : RichonlineTerminalReason::human_attack);
            return std::move(attack.packets);
        }
        if(script_hibernate) {
            // Lua 及响应转换已经成功；只提交这一份冬眠计划，不能再走通用扣卡路径。
            if(!hibernate_matches(*script_hibernate)) throw CodecError("lua_hibernate_snapshot_changed");
            commit_hibernate(*script_hibernate);
            if(rules.log) rules.log("lua_card_committed card=506 slot="+std::to_string(script_consumption->slot)+
                " hibernate=1");
            return messages;
        }
        if(script_consumption) {
            // Lua 完整返回且所有回包都分配成功后，才在同一事务提交库存与余额。
            const auto commit=[&] {
                if(rules.cards->inventory()!=script_consumption->source_inventory ||
                    (script_god_card && (phase!=Phase::roll || actor!=script_god_card->actor ||
                        active_counter!=script_god_card->calendar || turn_sequence!=script_god_card->turn ||
                        !active[actor] || npc_landing || npc_pending_counter ||
                        init.participants[actor].position!=script_god_card->position)) ||
                    (script_dismiss && (phase!=Phase::roll || actor!=script_dismiss->source ||
                        active_counter!=script_dismiss->calendar || turn_sequence!=script_dismiss->turn ||
                        !active[actor] || !active[script_dismiss->target] || npc_landing ||
                        status[actor]!=script_dismiss->source_status ||
                        rules.raw_authority->actor(script_dismiss->target)!=script_dismiss->target_raw)) ||
                    (script_jail && (phase!=Phase::roll || actor!=script_jail->source ||
                        active_counter!=script_jail->calendar || turn_sequence!=script_jail->turn ||
                        !active[actor] || !active[script_jail->target] ||
                        init.participants[script_jail->target].position!=script_jail->before_position ||
                        status[script_jail->target]!=script_jail->before_status ||
                        !rules.raw_authority->matches_jail_entry(script_jail->raw) ||
                        (script_jail->clock && !rules.npcs->matches_status_change(*script_jail->clock,status[script_jail->target])))) ||
                    (script_movement && (phase!=Phase::roll || actor!=script_movement->actor ||
                        active_counter!=script_movement->calendar || turn_sequence!=script_movement->turn ||
                        !active[actor] || init.participants[actor].position!=script_movement->position ||
                        init.participants[actor].direction!=script_movement->heading ||
                        status[actor]!=script_movement->status ||
                        (script_movement->ground_version && !rules.ground->matches(*script_movement->ground_version)))) ||
                    (script_property && !rules.property->combat_matches(*script_property)) ||
                    (script_street && !rules.property->street_effect_matches(*script_street)) ||
                    (script_ground && !rules.ground->matches(*script_ground)) ||
                    (script_motion && (rules.cards->inventory()!=script_motion->card.consumption.source_inventory ||
                        status[script_motion->target]!=script_motion->card.before.status ||
                        init.participants[script_motion->target].direction!=script_motion->card.before.heading ||
                        (script_motion->clock && !rules.npcs->matches_status_change(*script_motion->clock,status[script_motion->target])))) ||
                    (script_status && (status[script_status->target]!=script_status->before ||
                        (script_status->clock && !rules.npcs->matches_status_change(*script_status->clock,status[script_status->target])))) ||
                    std::ranges::any_of(script_positions,[&](const auto& position) {
                        return init.participants[position.slot].position!=position.before;})) return false;
                if(script_property && !rules.property->commit_combat(*script_property)) std::terminate();
                if(script_jail) {
                    const auto target=script_jail->target;
                    if(script_jail->applied && !rules.raw_authority->commit_jail_entry(script_jail->raw)) std::terminate();
                    if(script_jail->clock) {
                        if(!rules.npcs->commit_status_change(*script_jail->clock,status[target])) std::terminate();
                    } else status[target]=script_jail->after_status;
                    init.participants[target].position=script_jail->after_position;
                    if(script_jail->applied) reset_pet(target);
                }
                if(script_street && !rules.property->commit_street_effect(*script_street)) std::terminate();
                if(script_ground && !rules.ground->commit_prepared(*script_ground)) std::terminate();
                if(script_break_alliance && static_cast<std::int8_t>(relations1472[actor][*script_break_alliance])>0) {
                    relations1472[actor][*script_break_alliance]=0;relations1472[*script_break_alliance][actor]=0;
                }
                if(script_set_alliance) {
                    const auto [target,days]=*script_set_alliance;
                    relations1472[actor][target]=days;relations1472[target][actor]=days;
                }
                if(script_motion) {
                    if(script_motion->clock) {
                        if(!rules.npcs->commit_status_change(*script_motion->clock,status[script_motion->target])) std::terminate();
                    } else status[script_motion->target]=script_motion->card.after.status;
                    init.participants[script_motion->target].direction=script_motion->card.after.heading;
                    if(read_le(plain.first(2))==105) reset_pet(script_motion->target);
                    if(read_le(plain.first(2))==107 &&
                        static_cast<std::int8_t>(relations1472[actor][script_motion->target])>0)
                        relations1472[actor][script_motion->target]=relations1472[script_motion->target][actor]=0;
                    // 梦游卡对自己使用时，原生逻辑会先恢复掷骰阶段；若同时产生移动，后续路线提交会切回移动阶段。
                    if(read_le(plain.first(2))==107 && script_motion->target==actor)
                        await_roll();
                    if(script_motion->movement) {
                        route=std::move(script_motion->movement->route);checkpoint_cursor=0;authenticated_steps=0;phase=Phase::moving;controlled_roll_deadline.reset();
                    } else if(script_motion->card.continuation==RichonlineMotionCardContinuation::await_same_position17) {
                        route={};checkpoint_cursor=0;phase=Phase::stationary;
                    }
                }
                if(script_clear_relations) for(std::uint8_t other=0;other<active.size();++other) {
                    relations1472[*script_clear_relations][other]=0;
                    relations1472[other][*script_clear_relations]=0;
                }
                if(script_status) {
                    auto& current=status[script_status->target];
                    if(script_status->clock) {
                        if(!rules.npcs->commit_status_change(*script_status->clock,current)) std::terminate();
                    } else current=script_status->after;
                }
                if(script_god_card) {
                    if(script_god_card->npc==0) {
                        npc_pending_counter=script_god_card->calendar;npc_retired_counter.reset();
                        npc_deadline=script_god_card->deadline;phase=Phase::npc;
                    } else {npc_deadline.reset();phase=Phase::roll;}
                    controlled_roll_deadline.reset();
                }
                for(const auto& position:script_positions) {
                    init.participants[position.slot].position=position.after;
                    reset_pet(position.slot);
                }
                if(script_movement) static_cast<void>(commit_move(std::move(script_movement->move)));
                rules.cards->commit_inventory(script_consumption->remaining_inventory);return true;
            };
            if(script_funds.empty() ? !commit() : !rules.ledger->commit_batch(script_funds,commit))
                throw CodecError("lua_card_transaction_stale");
            if(rules.log) rules.log("lua_card_committed card="+std::to_string(script_consumption->card_id)+
                " slot="+std::to_string(script_consumption->slot)+" funds="+std::to_string(script_funds.size())+
                " property="+std::to_string(script_property.has_value())+
                " ground="+std::to_string(script_ground.has_value())+
                " street_properties="+std::to_string(script_street ? script_street->affected_properties() : 0)+
                " inventory_clear="+std::to_string(script_inventory_cleared)+
                " inventory_reorder="+std::to_string(script_shuffle.has_value())+
                " jail="+std::to_string(script_jail && script_jail->applied)+
                " npc_detach="+std::to_string(script_dismiss.has_value())+
                " god_card="+std::to_string(script_god_card.has_value())+
                " alliance="+std::to_string(script_set_alliance.has_value())+
                " positions="+std::to_string(script_positions.size())+
                " status="+std::to_string(script_status.has_value())+
                " movement="+std::to_string(script_movement.has_value())+
                " relations_clear="+std::to_string(script_clear_relations.has_value()));
        }
        if(script_dismiss) return npc_result({std::move(messages),RichonlineNpcContinuation::restore_action,
            RichonlineNpcWait::none,false,{}});
        return messages;
    }
    std::vector<Bytes> action(View plain) {
        if(boss_chest && plain.size()>=2 && read_le(plain.first(2))==0x11 && retired(plain)) return {};
        if(boss_chest && plain.size()==2 && read_le(plain)==2) {
            if(phase!=Phase::chest_ready) return {};
            actor=0;return begin_turn();
        }
        if(phase==Phase::finished && plain.size()>=2 && read_le(plain.first(2))==0x12 && retired(plain)) return {};
        if (phase == Phase::closed || phase == Phase::finished) throw CodecError("richonline_boss_session_closed");
        if (plain.size() < 2) throw CodecError("richonline_boss_action_truncated");
        if (phase==Phase::junction && retired(plain)) return {};
        const auto opcode = read_le(plain.first(2));
        // 宝箱阶段仅开放移动与手牌管理，不允许重新生成战斗、附身或地产事件。
        if(boss_chest && opcode>=92 && opcode!=103 && opcode!=137 && opcode!=138 && opcode!=139 &&
            opcode!=140 && opcode!=152 && opcode!=160)
            return {encode_richonline_dice_recovery400b(init.game_server_id)};
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
        case 100: case 119: {
            struct PlannedStreetCard {
                RichonlineBossProperty::PreparedStreetEffect property;
                RichonlineBossCards::PreparedConsumption consumption;
                Bytes response;
            };
            auto planned=prepare_card(opcode,[&] {
                require_local_controls();
                if(phase!=Phase::roll || actor!=init.local_slot || !active[actor] ||
                    status[actor].frozen || !rules.property || !rules.cards || plain.size()!=6 ||
                    read_le(plain.subspan(2,2))!=active_counter || plain[4]>=8 || plain[5]!=0)
                    throw CodecError("richonline_street_card_request_invalid");
                const auto consumption=rules.cards->prepare_consumption(static_cast<std::int8_t>(plain[4]),
                    opcode==100 ? 1035 : 1058);
                if(!consumption) throw CodecError("richonline_street_card_not_owned");
                auto property=rules.property->prepare_street_card(topology.cell(init.participants[actor].position).property_ref,
                    opcode==100 ? RichonlineBossProperty::StreetEffect::seal : RichonlineBossProperty::StreetEffect::price_rise);
                Bytes response;append_le(response,opcode==100 ? 0x40b4 : 0x40c7,2);append_le(response,init.game_server_id,2);
                response.push_back(plain[4]);response.push_back(plain[5]);
                return PlannedStreetCard{std::move(property),*consumption,std::move(response)};
            });
            if(!planned) return {encode_richonline_dice_recovery400b(init.game_server_id)};
            std::vector<Bytes> messages{std::move(planned->response)};
            if(rules.cards->inventory()!=planned->consumption.source_inventory ||
                !rules.property->street_effect_matches(planned->property))
                throw CodecError("richonline_street_card_stale");
            if(!rules.property->commit_street_effect(planned->property)) std::terminate();
            rules.cards->commit_inventory(planned->consumption.remaining_inventory);
            if(rules.log) rules.log(std::string(opcode==100 ? "richonline_seal_card_applied properties=" :
                "richonline_price_rise_card_applied properties=")+
                std::to_string(planned->property.affected_properties())+" days=5 mode=3");
            return messages;
        }
        case 99:
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
            const auto request=prepare_card(opcode,[&] {
                const auto parsed=parse_richonline_target_card(plain);
                require_local_controls();
                if(phase!=Phase::roll || actor!=init.local_slot || !rules.combat)
                    throw CodecError("richonline_boss_attack_card_out_of_phase");
                return parsed;
            });
            if(!request) return {encode_richonline_dice_recovery400b(init.game_server_id)};
            // Snapshot and shared combat commits must retain their real errors.
            auto refs=combat_refs();auto result=rules.combat->human_card(refs,*request,active_counter,true,rules.log);
            if(!result.bankrupt_actors.empty())
                return terminal(std::move(result.packets),std::move(result.bankrupt_actors),RichonlineTerminalReason::human_attack);
            return std::move(result.packets);
        }
        case 112: case 113: {
            const auto request=prepare_card(opcode,[&] {
                const auto parsed=parse_richonline_deity_card(plain);
                require_local_controls();
                if(phase!=Phase::roll || actor!=init.local_slot || !rules.npcs)
                    throw CodecError("richonline_boss_deity_card_out_of_phase");
                if(static_cast<std::uint8_t>(parsed.target_actor)>=init.participants.size())
                    throw CodecError("richonline_deity_card_target_invalid");
                if(parsed.calendar!=active_counter) throw CodecError("richonline_deity_card_calendar_mismatch");
                return parsed;
            });
            if(!request) return {encode_richonline_dice_recovery400b(init.game_server_id)};
            const auto target=static_cast<std::uint8_t>(request->target_actor);
            const auto source=landing_context(init.participants[actor].position);
            const auto target_position=init.participants[target].position;
            const auto distance_squared=[&](std::int16_t position) {
                const auto width=static_cast<std::int64_t>(topology.width());
                const auto dx=position%width-target_position%width;
                const auto dy=position/width-target_position/width;
                return dx*dx+dy*dy;
            };
            std::vector<std::int16_t> candidates;
            if(request->kind==RichonlineDeityCard::summon1047) {
                if(!rules.npc_summon_candidates) throw CodecError("richonline_boss_summon_policy_required");
                candidates=rules.npc_summon_candidates(source);
                for(const auto position:candidates)
                    if(!topology.cell(position).walkable) throw CodecError("richonline_boss_summon_candidate_cell_invalid");
                std::ranges::sort(candidates,[&](auto left,auto right) {
                    const auto a=distance_squared(left),b=distance_squared(right);
                    return a!=b ? a<b : left<right;
                });
            }
            auto result=rules.npcs->deity_card(plain,source,active_counter,status[target],raw_available(target),
                candidates,[](std::size_t) {return std::size_t{0};});
            if(result.summoned && rules.log) {
                const auto& god=*result.summoned;
                rules.log("richonline_summon_selected actor="+std::to_string(actor)+
                    " target="+std::to_string(target)+" target_position="+std::to_string(target_position)+
                    " npc="+std::to_string(god.id)+" npc_position="+std::to_string(god.position)+
                    " distance_squared="+std::to_string(distance_squared(god.position))+
                    " policy=nearest-target-grid-distance-then-position-v1");
            }
            return npc_result(std::move(result));
        }
        case 34:
            if(phase!=Phase::npc || !rules.npcs || !rules.npcs->awaiting_roulette())
                throw CodecError("richonline_boss_npc_roulette_out_of_phase");
            return npc_result(rules.npcs->handle(plain,actor,status[actor]));
        case 130: case 131: {
            const auto request=prepare_card(opcode,[&] {
                const auto calendar=opcode==130 ? decode_richonline_wealth_card(plain).calendar :
                    decode_richonline_fortune_card(plain).calendar;
                require_local_controls();
                if(phase!=Phase::roll || actor!=init.local_slot || !rules.npcs)
                    throw CodecError("richonline_boss_god_card_out_of_phase");
                if(calendar!=active_counter) throw CodecError("richonline_boss_god_card_counter_mismatch");
                return calendar;
            });
            if(!request) return {encode_richonline_dice_recovery400b(init.game_server_id)};
            const auto context=landing_context(init.participants[actor].position);
            return npc_result(opcode==130 ? rules.npcs->wealth_card(plain,context,status[actor]) :
                rules.npcs->fortune_card(plain,context,status[actor]));
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
            if(opcode==105) reset_pet(target);
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
            else commit_route_positions(*checkpoint);
            auto messages=sync_stopped_pet();
            auto bank=open_bank(request.position,request.calendar_counter,RichonlineGameBankVisit::passing,checkpoint);
            messages.insert(messages.end(),std::make_move_iterator(bank.begin()),std::make_move_iterator(bank.end()));
            return messages;
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
                const auto occupied=placement_occupied(request.position);
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
        case 125: case 126: case 127: case 128: case 129:
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
                const bool classic_conversion=opcode>=125 && opcode<=129;
                // NEW 40FD is pyramid (514/16); 40FE is garden (513/15).
                constexpr std::array<std::int8_t,6> conversion_kinds{11,12,13,14,16,15};
                const auto kind=conversion ? conversion_kinds.at(opcode-169) : std::int8_t{-1};
                const auto card_id=classic_conversion ? static_cast<int>(opcode)+939 : conversion ? 498+kind : opcode==163 ? 505 : opcode==166 ? 508 :
                    opcode==96 || opcode==97 || opcode==98 ? static_cast<int>(opcode)+935 : opcode==120 ? 1059 : opcode==134 ? 1077 :
                    opcode==101 ? 1036 : opcode==102 ? 1037 : opcode==114 ? 1051 : opcode==115 ? 1052 : 1062;
                consumption=rules.cards->prepare_consumption(static_cast<std::int8_t>(plain[4]),
                    static_cast<std::int16_t>(card_id));
                if(!consumption) throw CodecError("richonline_normal_card_not_owned");
                const auto response_opcode=classic_conversion || conversion || opcode==96 || opcode==97 || opcode==98 || opcode==120 || opcode==134 || opcode==163 ?
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
                } else if(classic_conversion) {
                    if(!rules.property) throw CodecError("richonline_conversion_card_authority_required");
                    const auto property_ref=static_cast<std::int16_t>(read_le(plain.subspan(6,2)));
                    building=rules.property->prepare_classic_conversion_card(property_ref,static_cast<std::int8_t>(opcode-123));
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
            struct PreparedPoisonRequest {
                RichonlineResearchCardRequest request;
                RichonlineResearchCardContext context;
                std::array<RichonlineRawActorState,8> raw;
                std::vector<RichonlinePoisonCell> footprint;
            };
            const auto prepared=prepare_card(opcode,[&] {
                require_local_controls();
                if(phase!=Phase::roll || actor!=init.local_slot || plain.size()!=8 ||
                    read_le(plain.subspan(2,2))!=active_counter)
                    throw CodecError("richonline_boss_research_card_out_of_phase");
                const auto request=decode_richonline_research_card(plain);
                if(!rules.poison || !rules.combat || !rules.poison_raw_actor)
                    throw CodecError("richonline_boss_poison_authority_required");
                const RichonlineResearchCardContext context{init.game_server_id,active_counter,
                    static_cast<std::int8_t>(actor),static_cast<std::int8_t>(init.local_slot),true,
                    active[actor] && !richonline_landing_controlled(status[actor])};
                std::array<RichonlineRawActorState,8> raw{};
                for(std::uint8_t slot=0;slot<active.size();++slot) raw[slot]=rules.poison_raw_actor(slot);
                auto footprint=richonline_poison_map_footprint(topology,init.participants[actor].position,rules.poison->range);
                return PreparedPoisonRequest{request,context,std::move(raw),std::move(footprint)};
            });
            if(!prepared) return {encode_richonline_dice_recovery400b(init.game_server_id)};
            auto refs=combat_refs();
            auto result=rules.combat->poison_card(refs,prepared->request,prepared->context,poison_use_count,
                *rules.poison,prepared->footprint,prepared->raw,relations1472,true,rules.log);
            if(!result.bankrupt_actors.empty())
                return terminal(std::move(result.packets),std::move(result.bankrupt_actors),RichonlineTerminalReason::poison_card);
            return std::move(result.packets);
        }
        case 155: case 157: {
            std::optional<RichonlineResearchTrapPlan> planned;
            try {
                require_local_controls();
                if(phase!=Phase::roll || actor!=init.local_slot || plain.size()!=8 ||
                    read_le(plain.subspan(2,2))!=active_counter)
                    throw CodecError("richonline_boss_research_card_out_of_phase");
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
                        const auto& cell=topology.cell(target);
                        return RichonlineResearchTrapCell{cell.walkable,placement_occupied(target),cell.static_type};
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
            if(boss_chest) {
                chest_stops.push_back({request.calendar_counter,static_cast<std::uint16_t>(endpoint)});
                if(!stationary) commit_route_positions(route.landings.size()-1);
                landing_counter=request.calendar_counter;route={};
                Bytes stop;append_le(stop,0x4013,2);append_le(stop,init.game_server_id,2);
                append_le(stop,static_cast<std::uint16_t>(endpoint),2);
                auto messages=sync_stopped_pet();messages.insert(messages.begin(),std::move(stop));
                if(endpoint==*boss_chest) return finish_chest(std::move(messages),true);
                return resolve({std::move(messages),RichonlineLandingProgress::complete});
            }
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
            else if(!stationary) commit_route_positions(route.landings.size()-1);
            return ground_landing(landing,sync_stopped_pet());
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
            auto sync=sync_stopped_pet();
            result.packets.insert(result.packets.begin(),std::make_move_iterator(sync.begin()),std::make_move_iterator(sync.end()));
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
    if(rules.equipment_healing && !rules.ledger) throw CodecError("richonline_equipment_healing_ledger_required");
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
    if(startup.human_profile_slots) {
        const auto pet=(*startup.human_profile_slots)[0];
        if(pet>0 && pet<=0x7fffffffU) {
            if(!state->rules.raw_authority)
                throw RichonlineEquipmentError("richonline_pet_actor_authority_required",0,pet);
            state->pets[startup.init.local_slot].equipped=true;
            state->reset_pet(startup.init.local_slot);
        }
        const auto vehicle=(*startup.human_profile_slots)[1];
        if(vehicle>0 && vehicle<=0x7fffffffU)
            state->human_dice_count=state->rules.payment_equipment.dice_vehicle==RichonlineDiceVehicle::motorcycle?2:3;
    }
    if(state->rules.npcs) state->rules.npcs->configure_placement_reservations([weak=std::weak_ptr<Turns>(state)] {
        const auto owner=weak.lock();
        if(!owner) throw CodecError("richonline_pet_turn_owner_expired");
        return owner->placement_reservations();
    });
    state->junction.emplace(startup.init.game_server_id);
    state->active_counter=static_cast<std::uint16_t>(startup.snapshot.calendar_counter);
    return {startup.init,startup.snapshot,startup.envelope,
        [state] { return state->opening(); },
        [state](const Envelope299&,View plain) { return state->script_action(plain); },
        [state] { state->phase = Phase::closed; state->route = {}; },
        [state] { return state->poll(); },
        [state](View plain) { return state->retired(plain); }};
}
}
