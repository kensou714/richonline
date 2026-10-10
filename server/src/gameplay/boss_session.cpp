#include "richonline_boss_session.hpp"
#include "richonline_boss_landing.hpp"
#include "richonline_boss_property.hpp"
#include "richonline_boss_shop.hpp"
#include "richonline_game_ledger.hpp"
#include "richonline_motion_card.hpp"
#include "richonline_chance_landing.hpp"
#include "diagnostic_log.hpp"
#include "richonline_opening_hand.hpp"
#include "richonline_mine_landing_policy.hpp"
#include "richonline_portal_landing.hpp"
#include "richonline_special_session.hpp"
#include "original_game_values.hpp"
#include "richonline_research_cards.hpp"
#include <algorithm>
#include <bit>

namespace richnet {
RichonlineStartupPlan make_richonline_boss_session(const std::filesystem::path& resources,
    const RichonlineBossStartup& startup,const RichonlineMapPackage& package,
    const RichonlineBossSessionPolicy& policy,
    std::shared_ptr<const RichonlineChanceResources> chance,ControlLog log) {
    log=nonthrowing_diagnostic_log(std::move(log));
    if (static_cast<bool>(policy.terminal)!=policy.result_display.has_value())
        throw CodecError("richonline_terminal_display_policy_required");
    auto delivery=policy.result_display ? std::make_shared<RichonlineResultDeliveryGate>(*policy.result_display) : nullptr;
    const auto& extension=startup.room.description.extension;
    if (extension.size()!=88) throw CodecError("richonline_boss_E88_invalid");
    const auto category=read_le(View(extension).subspan(68,4));
    const auto stage=package.load_stage(resources,category);
    const auto name_end=std::find(extension.begin(),extension.begin()+32,std::uint8_t{0});
    if (std::string(extension.begin(),name_end)!=stage.map_name ||
        !std::equal(stage.signature.begin(),stage.signature.end(),extension.begin()+32))
        throw CodecError("richonline_map_package_room_mismatch");
    if (!package.runtime_enabled) {
        if (log) log("richonline_map_package_pending",{{"package",package.id},{"map",package.map_name},
            {"category",category},{"level","warning"}});
        throw CodecError("richonline_map_package_runtime_incomplete");
    }
    auto topology=load_richonline_road_topology(resources/"Map"/stage.map_name);
    std::function<std::optional<RichonlinePortalLandingPlan>(const RichonlineLandingContext&)> portal_landing;
    const auto& static_types=package.resource_rules.expected_static_types;
    if (std::find(static_types.begin(),static_types.end(),28)!=static_types.end() ||
        std::find(static_types.begin(),static_types.end(),58)!=static_types.end() ||
        std::find(static_types.begin(),static_types.end(),61)!=static_types.end()) {
        const auto map_rules=load_richonline_map_rule_resources(resources,package,category);
        if (!policy.portal_scripted_state)
            throw CodecError("richonline_boss_portal_scripted_state_required");
        portal_landing=[topology,pairs=map_rules.portals,read_state=policy.portal_scripted_state,
            game=startup.init.game_server_id](const RichonlineLandingContext& context)
            ->std::optional<RichonlinePortalLandingPlan> {
            if (context.static_type!=28 && context.static_type!=58 && context.static_type!=61) return {};
            const auto raw=read_state();
            if (raw<-1 || raw>2) throw CodecError("richonline_boss_portal_scripted_state_invalid");
            if(context.static_type==58) return plan_richonline_random_teleport_landing(game,topology,context,raw!=-1);
            return plan_richonline_portal_landing(game,topology,
                pairs[context.static_type==28 ? 0U : 1U],context,raw!=-1);
        };
    }
    std::vector<RichonlineGameFunds> initial_funds;
    for (const auto& slot:startup.snapshot.slots)
        initial_funds.push_back({slot.cash,slot.deposit,slot.tickets,std::nullopt});
    const auto charges=load_richonline_gold_charges(resources/"Data/GoldCharge.kpd");
    if (policy.payment)
        initial_funds.at(startup.init.local_slot).reserve=richonline_initial_reserve(
            policy.payment->account_gold,stage.pawn_gold,charges);
    auto ledger=std::make_shared<RichonlineGameLedger>(std::move(initial_funds));
    if(policy.terminal)policy.terminal->bind_earned_cash(ledger,startup.init.local_slot);
    auto payment=policy.payment ? std::make_shared<RichonlineGamePayment>(ledger,startup.init.local_slot,
        charges,policy.payment->debit) : nullptr;
    auto balances=std::make_shared<RichonlineBossLandingState>(startup.init.game_server_id,ledger);
    std::shared_ptr<RichonlineMerchantSession> merchant;
    if(std::find(static_types.begin(),static_types.end(),57)!=static_types.end()) {
        if(!policy.portal_scripted_state)
            throw CodecError("richonline_boss_merchant_scripted_state_required");
        merchant=std::make_shared<RichonlineMerchantSession>(topology,ledger,startup.init.game_server_id,
            startup.room.key,std::string(package.id),log,
            [read_state=policy.portal_scripted_state](const RichonlineLandingContext&)->std::optional<std::int8_t> {
                const auto raw=read_state();
                if(raw<-1 || raw>2) throw CodecError("richonline_boss_merchant_scripted_state_invalid");
                return static_cast<std::int8_t>(raw);
            });
    }
    auto cards=policy.cards ? std::make_shared<RichonlineBossCards>(chance,
        startup.init.game_server_id,package.configure(*policy.cards)) : nullptr;
    if(cards) {
        if(!package.closed_chance) throw CodecError("richonline_card_tile_map_policy_required");
        cards->configure_tile_rewards(package.closed_chance->playable_reward_cards,policy.random);
        if(log) log("richonline_card_tile_policy",{{"room",startup.room.key},{"package",package.id},
            {"selection_policy","native-uniform-playable-resource-cards-v1"},{"candidates",cards->tile_reward_cards()}});
    }
    std::optional<RichonlineOpeningHandPlan> opening_hand;
    if (cards && package.opening_hand) {
        opening_hand=prepare_richonline_opening_hand(startup.init.game_server_id,*package.opening_hand,*chance);
        if (std::any_of(opening_hand->inventories[1].begin(),opening_hand->inventories[1].end(),
            [](const auto& slot){return slot.card_id!=-1;}))
            throw CodecError("richonline_synthetic_opening_inventory_unimplemented");
        cards->commit_inventory(opening_hand->inventories[0]);
    }
    auto shop=cards ? std::make_shared<RichonlineBossShop>(resources,*cards,startup.init.game_server_id,
        ledger,[] { return RichonlineBossShop::Clock::now(); },std::array<std::uint8_t,2>{0,255},policy.random) : nullptr;
    if (shop && payment) {
        auto next_refresh=std::make_shared<std::uint64_t>(0);
        shop->configure_refresh(charges,[payment,next_refresh,expected_cost=charges.require(4),prefix=policy.payment->operation_prefix](std::uint32_t cost) {
            if (expected_cost<0 || static_cast<std::uint32_t>(expected_cost)!=cost)
                throw CodecError("richonline_shop_charge_policy_mismatch");
            const auto result=payment->shop_refresh(prefix+":shop:"+std::to_string(++*next_refresh));
            if (result.status==RichonlinePaymentStatus::recovery_required)
                throw CodecError("richonline_payment_recovery_required");
            if (result.status!=RichonlinePaymentStatus::committed) return false;
            return true;
        });
    }
    auto property=std::make_shared<RichonlineBossProperty>(resources,startup.init.game_server_id,
        ledger,stage);
    property->configure_construction(startup.init.participants.at(0).building_skill_caps,cards);
    property->enable_human_decisions(std::chrono::milliseconds{static_cast<std::int64_t>(stage.wait_seconds)*1000},
        [] { return RichonlineBossProperty::Clock::now(); });
    const auto package_id=std::string(package.id);
    RichonlineBossTurnRules rules{policy.opaque_turn7,policy.inactive_ui_dice,policy.route_wire,policy.random,
        [log,property,balances,merchant,shop,cards,package_id,key=startup.room.key,game=startup.init.game_server_id](const RichonlineLandingContext& landing) {
            try {
                if (auto controlled=resolve_richonline_controlled_static_landing(game,landing))
                    return std::move(*controlled);
                if ((landing.static_type==28 || landing.static_type==58 || landing.static_type==61) && landing.property_ref==-1) {
                    Bytes stop;append_le(stop,0x4013,2);append_le(stop,game,2);
                    append_le(stop,static_cast<std::uint16_t>(landing.position),2);
                    return RichonlineLandingResult{{std::move(stop)},RichonlineLandingProgress::complete};
                }
                if(merchant) if(auto result=merchant->land(landing)) return std::move(*result);
                if (auto result=property->land(landing)) {
                    const auto building=property->building(landing.property_ref);
                    if (log) log("richonline_property_landed",{{"room",key},{"actor_slot",landing.actor_slot},
                        {"property_ref",landing.property_ref},{"owner",property->owner(landing.property_ref).value_or(255)},
                        {"building_kind",building ? building->kind : -1},{"building_level",building ? building->level : 0},
                        {"pending_opcode",result->pending_opcode.value_or(0)},{"package",package_id},{"level","info"}});
                    return std::move(*result);
                }
                if (shop) if (auto result=shop->land(landing)) {
                    if (log && shop->active()) {
                        auto offers=nlohmann::json::array();
                        for (const auto& offer:shop->offers()) offers.push_back({{"card",offer.card_id},
                            {"count",offer.count},{"price",offer.card_id==-1 ? 0U : shop->card_price(offer.card_id)}});
                        auto inventory=nlohmann::json::array();
                        for (const auto& slot:cards->inventory()) inventory.push_back({{"card",slot.card_id},{"count",slot.count}});
                        log("richonline_shop_opened",{{"room",key},{"package",package_id},{"position",landing.position},
                            {"tickets",shop->points()},{"offers",offers},{"inventory",inventory},{"duration_ms",10000},{"level","info"}});
                    }
                    return std::move(*result);
                }
                return balances->land(landing);
            } catch (const CodecError& error) {
                if (log) log("richonline_boss_landing_rejected",{{"room",key},{"actor_slot",landing.actor_slot},
                    {"position",landing.position},{"static_type",landing.static_type},{"property_ref",landing.property_ref},
                    {"road_degree",landing.road_degree},{"occupied",landing.occupied_by_other_actor},{"reason",error.what()},
                    {"package",package_id},{"runtime_client_verified",false},{"level","warning"}});
                throw;
            }
        },[property,shop,cards,log,package_id,key=startup.room.key](View plain) {
            const auto opcode=read_le(plain.first(2));
            if (opcode==0x20 || opcode==0x37 || opcode==0x38 || opcode==0x39) return property->decide(plain);
            if (shop && shop->active()) {
                const auto before=shop->points();
                const auto index=plain.size()>=5 ? static_cast<int>(std::bit_cast<std::int8_t>(plain[4])) : -1;
                std::int16_t card=-1,count=0;
                if (opcode==0x30 && index>=0 && index<12) {
                    const auto& offer=shop->offers()[static_cast<std::size_t>(index)];
                    card=offer.card_id; count=offer.count;
                } else if (opcode==0x31 && index>=0 && index<8) {
                    const auto& slot=cards->inventory()[static_cast<std::size_t>(index)];
                    card=slot.card_id; count=slot.count;
                }
                const auto price=card==-1 ? 0U : shop->card_price(card);
                const auto empty=std::count_if(cards->inventory().begin(),cards->inventory().end(),
                    [](const auto& slot) { return slot.card_id==-1; });
                auto result=shop->handle(plain);
                if (log) log("richonline_shop_request",{{"room",key},{"package",package_id},{"opcode",opcode},
                    {"index",index},{"card",card},{"count",count},{"price",price},{"sale_refund",opcode==0x31 ? price/2 : 0U},
                    {"tickets_before",before},{"tickets_after",shop->points()},{"empty_slots_before",empty},
                    {"decision",shop->last_decision()},{"active",shop->active()},{"level","info"}});
                return result;
            }
            if (log) log("richonline_boss_event_unimplemented",{{"room",key},{"opcode",opcode},
                {"plain_bytes",plain.size()},{"package",package_id},{"runtime_client_verified",false},{"level","warning"}});
            throw CodecError("richonline_boss_event_unimplemented");
        }};
    rules.portal_landing=portal_landing;
    rules.research_turn_started=[property](std::uint8_t actor){property->advance_research(actor);};
    rules.cards=std::move(cards);
    rules.property=property;
    if(startup.human_profile_slots) {
        const auto equipment=(*startup.human_profile_slots)[2];
        rules.human_purchase_half_price=equipment>0 && equipment<=0x7fffffffU;
    }
    rules.raw_authority=policy.raw_authority;
    const auto card_values=load_original_game_values(resources/"Data"/"GValue.kpd");
    const auto jail_days=card_values.require(10),alliance_days=card_values.require(11);
    if(jail_days<1 || jail_days>127 || alliance_days<1 || alliance_days>127)
        throw CodecError("richonline_auxiliary_card_duration_invalid");
    rules.jail_days=static_cast<std::uint8_t>(jail_days);
    rules.alliance_days=static_cast<std::uint8_t>(alliance_days);
    if (rules.cards && policy.hibernate_raw_actor)
        rules.hibernate=std::make_shared<const RichonlineHibernateTurnPolicy>(
            RichonlineHibernateTurnPolicy{chance,RichonlineHibernateRules::load(resources),policy.hibernate_raw_actor});
    if (rules.cards)
        rules.motion_cards=std::make_shared<const RichonlineMotionCardRules>(RichonlineMotionCardRules::load(resources));
    if (rules.cards) {
        if (!package.closed_chance) throw CodecError("richonline_map_chance_policy_unimplemented");
        const auto& map_chance=*package.closed_chance;
        auto event_table=std::make_shared<const RichonlineChanceEventTable>(RichonlineChanceEventTable::load(resources));
        const auto status_rules=RichonlineStatusRules::load(resources);
        const auto chance_policy=make_richonline_closed_chance_policy(*event_table,stage.map_name,
            map_chance.playable_reward_cards,map_chance.enable_motion_status,policy.cards->opaque6_7);
        rules.chance_landing=[event_table,status_rules,chance_policy,chance,ledger,cards=rules.cards,
            random=policy.random,game=startup.init.game_server_id,log,package_id,key=startup.room.key]
            (const RichonlineLandingContext& context)->std::optional<RichonlineLandingResult> {
            // Only road events with no subsequent property or actor collision
            // can proceed directly to the shared final-junction phase.
            if (context.property_ref!=-1 || (context.occupied_by_other_actor && !context.collision_resolved) || context.road_degree==0 || context.road_degree>4)
                return {};
            auto attempt=prepare_richonline_chance_landing(*event_table,*chance,status_rules,chance_policy,
                context,game,ledger->snapshot(context.actor_slot),cards->inventory(),random);
            if (attempt.disposition==RichonlineChanceLandingDisposition::not_applicable) return {};
            if (!attempt.prepared) throw CodecError("richonline_chance_no_closed_event");
            auto& prepared=*attempt.prepared;
            if (cards->inventory()!=prepared.expected_inventory)
                throw CodecError("richonline_chance_inventory_changed");
            Bytes stop; append_le(stop,0x4013,2); append_le(stop,game,2);
            append_le(stop,static_cast<std::uint16_t>(context.position),2);
            RichonlineLandingResult result{{std::move(stop),std::move(prepared.packet)},RichonlineLandingProgress::complete,{},
                RichonlineLandingStatusChange{prepared.expected_status,prepared.updated_status}};
            ledger->commit(context.actor_slot,prepared.expected_funds,prepared.updated_funds);
            cards->commit_inventory(prepared.updated_inventory);
            if (log) log("richonline_chance_completed",{{"room",key},{"package",package_id},{"actor",context.actor_slot},
                {"event",prepared.event},{"category",prepared.category},{"selection_policy",prepared.policy},
                {"excluded_events",attempt.excluded_events},{"level","info"}});
            return result;
        };
    }
    rules.payment=payment;
    if (stage.boss.max_dice<1 || stage.boss.max_dice>3)
        throw CodecError("richonline_boss_max_dice_invalid");
    rules.boss_dice_count=static_cast<std::uint8_t>(stage.boss.max_dice);
    if (policy.payment) {
        rules.payment_operation_prefix=policy.payment->operation_prefix;
        rules.payment_equipment=policy.payment->equipment;
    }
    rules.ledger=ledger;
    if (policy.terminal) {
        rules.month_limit_days=static_cast<std::uint8_t>(stage.game_months*30U);
        rules.terminal=[terminal=policy.terminal](const RichonlineTurnTerminalContext& context) {
            std::vector<std::int8_t> actors;
            for (const auto actor:context.bankrupt_actors) actors.push_back(static_cast<std::int8_t>(actor));
            const auto step=context.reason==RichonlineTerminalReason::month_limit ?
                terminal->month_limit() : terminal->bankrupt(actors);
            if (step.action==RichonlineTerminalAction::abort_live_game)
                throw CodecError(step.diagnostic);
            if (step.action!=RichonlineTerminalAction::deliver)
                throw CodecError("richonline_single_boss_terminal_not_complete");
            const auto* next=terminal->next_transmission();
            if (!next || next->transport!=RichonlineSettlementTransport::game)
                throw CodecError("richonline_terminal_game_messages_missing");
            // Build all messages without advancing the durable cursor. The
            // transport observer confirms each successfully sent frame later.
            return RichonlineTurnTerminalResult{terminal->pending_game_messages(),true};
        };
    }
    std::shared_ptr<RichonlineGroundObjects> ground;
    if (policy.npcs || policy.combat || rules.cards) {
        std::vector<std::int16_t> roads;
        for (const auto& cell:topology.cells()) if (cell.walkable) roads.push_back(cell.position);
        ground=std::make_shared<RichonlineGroundObjects>(std::move(roads));
    }
    rules.ground=ground;
    rules.ground_card_visible=policy.ground_card_visible;
    if(rules.cards && ground && policy.ground_card_visible && chance &&
        chance->automatic_card_eligible(stage.map_name,1181))
        rules.ice_traps=std::make_shared<const RichonlineResearchTrapRules>(RichonlineResearchTrapRules::load(resources));
    if (policy.npcs || policy.combat || rules.ice_traps) {
        if (!rules.cards || !chance) throw CodecError("richonline_npc_cards_required");
        // Validate the continuation before an NPC changes ground occupancy,
        // cards, possession or funds. This is a capability check, not a
        // cross-module transaction or a substitute for collision handling.
        rules.npc_landing_preflight=[topology,property,shop,balances,merchant,portal_landing,game=startup.init.game_server_id,
            has_bank=policy.bank.has_value()](const RichonlineLandingContext& context) {
            if (context.occupied_by_other_actor && !context.collision_resolved)
                throw CodecError("richonline_boss_npc_collision_continuation_unimplemented");
            if (context.game_mode!=3 || context.actor_slot>=2 || context.position<0 ||
                context.road_degree==0 || context.road_degree>4)
                throw CodecError("richonline_boss_npc_landing_context_invalid");
            const auto& cell=topology.cell(context.position);
            if (!cell.walkable || cell.static_type!=context.static_type || cell.property_ref!=context.property_ref)
                throw CodecError("richonline_boss_npc_landing_context_invalid");
            if (cell.static_type==28 || cell.static_type==58 || cell.static_type==61) {
                if (!portal_landing || !portal_landing(context))
                    throw CodecError("richonline_boss_portal_plan_missing");
                if (context.property_ref==-1) return;
            }
            if (resolve_richonline_controlled_static_landing(game,context)) return;
            if (merchant && merchant->validate_landing(context)) return;
            if (cell.static_type==9 && has_bank && cell.property_ref==-1) return;
            if (property->validate_landing(context)) return;
            if (shop && shop->validate_landing(context)) return;
            if (context.property_ref==-1 &&
                ((!context.synthetic_actor && richonline_boss_card_reward_tile(cell.static_type)) ||
                 ((cell.static_type==68 || cell.static_type==69 || cell.static_type==70) &&
                  context.actor_status.possession!=7 && !context.actor_status.sleepwalking && !context.actor_status.frozen)))
                return;
            balances->validate_landing(context);
        };
    }
    if (policy.npcs) {
        const auto maximum=load_original_game_values(resources/"Data/GValue.kpd").require(37);
        if(maximum<1 || maximum>127) throw CodecError("richonline_temple_maximum_invalid");
        auto npc_policy=*policy.npcs;
        const bool aura=rules.terminal && policy.hibernate_raw_actor;
        if(aura) {
            rules.npc_aura=RichonlineNpcAuraRules::load(resources);
            rules.npc_aura_raw_actor=policy.hibernate_raw_actor;
            npc_policy.temple_aura_affix=std::array{load_richonline_npc_affix(resources,4),
                load_richonline_npc_affix(resources,6)};
        }
        property->enable_temple_possession(static_cast<std::uint8_t>(maximum),aura,
            {true,true,npc_policy.badluck.has_value(),true});
        // NEW112 sends no viewport or god position. The client checks its own
        // viewport; this explicit server policy chooses among present map gods.
        rules.npc_summon_candidates=[ground](const RichonlineLandingContext&) {
            return ground->positions();
        };
        rules.npcs=std::make_shared<RichonlineNpcSession>(startup.init.game_server_id,stage.map_name,
            RichonlineNpcRules::load(resources),chance,
            std::make_shared<const RichonlineChanceEventTable>(RichonlineChanceEventTable::load(resources)),
            ledger,rules.cards,ground,std::move(npc_policy));
    }
    if (policy.combat) {
        if (!rules.cards || !rules.terminal || !startup.human_profile_slots || !package.combat)
            throw CodecError("richonline_boss_combat_session_capability_required");
        auto combat_policy=*policy.combat;
        const auto mine_landings=std::make_shared<const RichonlineMineLandingPolicy>(topology,3,
            startup.init.local_slot,rules.npc_landing_preflight);
        const auto configured_mines=combat_policy.mine_landing_supported;
        combat_policy.mine_landing_supported=[mine_landings,configured_mines](std::int16_t position,
            const RichonlineCombatSessionView& state) {
            return mine_landings->supports(position,state) &&
                (!configured_mines || configured_mines(position,state));
        };
        auto world=make_richonline_combat_world(resources,topology,stage,*startup.human_profile_slots,
            *package.combat,property,std::move(combat_policy));
        rules.combat=std::make_shared<RichonlineCombatBridge>(startup.init.game_server_id,ledger,rules.cards,
            ground,property,std::move(world.world),std::move(world.boss));
        rules.combat_random=[random=policy.random] {
            RichonlineBossAttackRandomness value;
            for (auto& draw:value.rolls) draw=static_cast<std::uint8_t>(random(100));
            value.bounded=random;
            return value;
        };
        rules.combat_capabilities=[capabilities=std::move(world.capabilities)]
            (std::uint8_t actor,const RichonlineActorStatus& status) {
            return capabilities(actor,status,true);
        };
    }
    if(rules.combat && rules.terminal && rules.cards && ground && policy.ground_card_visible && chance &&
        chance->automatic_card_eligible(stage.map_name,1183))
        rules.fire_traps=std::make_shared<const RichonlineFireTrapRules>(RichonlineFireTrapRules::load(resources));
    if(rules.combat && rules.terminal && rules.cards && policy.hibernate_raw_actor && chance &&
        chance->automatic_card_eligible(stage.map_name,1182)) {
        rules.poison=std::make_shared<const RichonlinePoisonRules>(RichonlinePoisonRules::load(resources));
        rules.poison_raw_actor=policy.hibernate_raw_actor;
    }
    if (policy.timed_bombs) {
        if (!rules.combat || !rules.cards || !policy.timed_bombs->resources ||
            !policy.timed_bombs->step_context)
            throw CodecError("richonline_boss_timed_bomb_session_capability_required");
        rules.timed_bombs=policy.timed_bombs;
    }
    if (policy.bank)
        rules.bank=std::make_shared<RichonlineGameBank>(startup.init.game_server_id,*policy.bank,
            [] { return RichonlineGameBank::Clock::now(); });
    rules.log=[log,package_id,key=startup.room.key](const std::string& detail) {
        if (log) log("richonline_boss_action",{{"room",key},{"package",package_id},{"detail",detail},{"level","warning"}});
    };
    rules.poll=[property,shop,log,package_id,key=startup.room.key] {
        if (shop && shop->active()) {
            auto result=shop->poll();
            if (result) {
                if (log) log("richonline_shop_timeout",{{"room",key},{"package",package_id},
                    {"decision",shop->last_decision()},{"tickets",shop->points()},{"level","info"}});
            }
            return result;
        }
        auto result=property->poll();
        if (result && log) log("richonline_property_timeout",{{"room",key},{"package",package_id},{"decision","decline"},{"level","info"}});
        return result;
    };
    auto plan=make_richonline_boss_turns(startup,std::move(topology),std::move(rules));
    plan.map_loading=policy.map_loading;
    if (opening_hand) {
        plan.map_ready=[ready=std::move(plan.map_ready),packets=std::move(opening_hand->synchronization)] {
            auto turns=ready();
            if (turns.empty()) return turns;
            std::vector<Bytes> messages;
            messages.reserve(packets.size()+turns.size());
            messages.insert(messages.end(),packets.begin(),packets.end());
            messages.insert(messages.end(),std::make_move_iterator(turns.begin()),std::make_move_iterator(turns.end()));
            return messages;
        };
    }
    if (policy.terminal) {
        auto terminal=policy.terminal;
        plan.map_ready=[ready=std::move(plan.map_ready),terminal] {
            if (terminal->phase()==RichonlineTerminalPhase::prepared) terminal->activate();
            return ready();
        };
        plan.sent=[terminal,delivery](View plain) {
            const auto* next=terminal->next_transmission();
            if (next && next->transport==RichonlineSettlementTransport::game &&
                std::equal(plain.begin(),plain.end(),next->game_plain.begin(),next->game_plain.end()))
                terminal->confirm_sent(next->sequence);
            next=terminal->next_transmission();
            if (next && next->transport==RichonlineSettlementTransport::lobby)
                delivery->game_frames_sent();
        };
        plan.game_finished=[terminal,delivery] {
            const auto* next=terminal->next_transmission();
            return next && next->transport==RichonlineSettlementTransport::lobby && delivery->ready();
        };
        plan.terminal_pending=[terminal] {
            const auto phase=terminal->phase();
            return phase==RichonlineTerminalPhase::delivering || phase==RichonlineTerminalPhase::finished ||
                phase==RichonlineTerminalPhase::recovery_required;
        };
        plan.lobby_sent=[terminal](const Frame& frame) {
            const auto* next=terminal->next_transmission();
            if (next && next->transport==RichonlineSettlementTransport::lobby && next->lobby &&
                frame.wire_type==next->lobby->wire_type && frame.payload==next->lobby->payload)
                terminal->confirm_sent(next->sequence);
        };
        plan.disconnected=[close=std::move(plan.disconnected),terminal,log,key=startup.room.key] {
            close();
            const auto* next=terminal->next_transmission();
            if (next && next->transport==RichonlineSettlementTransport::lobby) {
                if (log) log("richonline_terminal_transport_closed",{{"room",key},
                    {"reason","game_results_sent_waiting_for_lobby_58"},{"level","info"}});
                return;
            }
            const auto abandoned=terminal->abandon("game_connection_closed");
            if (log && !abandoned.diagnostic.empty())
                log("richonline_terminal_cleanup",{{"room",key},{"reason",abandoned.diagnostic},{"level","warning"}});
        };
    }
    return plan;
}
}
