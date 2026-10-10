#include "richonline_npc_session.hpp"
#include "richonline_card_protection.hpp"
#include <algorithm>
#include <iostream>

namespace {
using namespace richnet;
void check(bool ok,const char* reason) {if(!ok) throw std::runtime_error(reason);}
template<class F> void rejects(F fn) {try {fn();}catch(const std::exception&){return;}throw std::runtime_error("expected rejection");}
struct Fixture {
    std::shared_ptr<const RichonlineChanceResources> resources;
    std::shared_ptr<const RichonlineChanceEventTable> events;
    std::shared_ptr<RichonlineGameLedger> ledger;
    std::shared_ptr<RichonlineBossCards> cards;
    std::shared_ptr<RichonlineGroundObjects> ground;
    RichonlineNpcRules rules;
    RichonlineNpcSessionPolicy policy;
    std::array<RichonlineActorStatus,2> statuses{};
    std::unique_ptr<RichonlineNpcSession> session;
    explicit Fixture(const std::filesystem::path& root,std::int16_t amount=70)
        :resources(std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root))),
        events(std::make_shared<const RichonlineChanceEventTable>(RichonlineChanceEventTable::load(root))),
        ledger(std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{100,1000,150,90},{40,100,0,80}})),
        cards(std::make_shared<RichonlineBossCards>(resources,0x1234,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}})),
        ground(std::make_shared<RichonlineGroundObjects>(std::vector<std::int16_t>{114,121,179,187,226,237})),
        rules(RichonlineNpcRules::load(root)),
        policy{{0,0,0,3,3,{0,1,3},0xa7,0xa8,0xc7,0xc8,false},17,{1038,1039},{10,20},
            {load_richonline_npc_affix(root,0),load_richonline_npc_affix(root,1)},"fixture-fixed-transfer",
            [amount](std::uint8_t,std::int8_t,const auto&){return amount;}} {
        reset();
    }
    void reset() {
        session=std::make_unique<RichonlineNpcSession>(0x1234,"BS_1_1.emp",rules,resources,events,ledger,cards,ground,policy);
        check(session->initial().messages.empty(),"zero_initial_policy_spawned");
        session->actor_begin(0,1,statuses[0]);session->actor_begin(1,1,statuses[1]);
    }
    RichonlineLandingContext context(std::uint8_t actor=0,std::int16_t position=114) const {
        return {actor,position,68,-1,3,actor==1,2,false,statuses[actor]};
    }
};
void fortune_lifecycle(const std::filesystem::path& root) {
    Fixture f(root); f.ground->place(114,{3,0xa7,0xa8});
    const auto funds0=f.ledger->snapshot(0),funds1=f.ledger->snapshot(1);
    const auto attached=f.session->landing(f.context(),0x4567,f.statuses[0]);
    check(attached && attached->wait==RichonlineNpcWait::none && attached->sent_stop4013 &&
        attached->continuation==RichonlineNpcContinuation::landing_phase1,"fortune_skipped_static_followup");
    check(attached->messages==std::vector<Bytes>{{0x13,0x40,0x34,0x12,114,0},{0x23,0x40,0x34,0x12,0x0e,4,0x0f,4}},"fortune_wire_sequence");
    check(f.statuses[0].possession==3 && f.cards->inventory()[0]==RichonlineChanceCardSlot{1038,1} &&
        f.cards->inventory()[1]==RichonlineChanceCardSlot{1039,1},"fortune_shared_inventory_or_status_missing");
    check(f.ledger->snapshot(0)==funds0 && f.ledger->snapshot(1)==funds1 && f.ground->snapshot().objects.empty(),"fortune_changed_money_or_left_ground");
    const auto inventory=f.cards->inventory();
    check(!f.session->landing(f.context(),0x4567,f.statuses[0]) && f.cards->inventory()==inventory,"duplicate_pickup_rewarded_again");
    const auto card=f.cards->prepare_use({0x4567,0,0,3,0xa5});
    check(card && card->die==3,"fortune_reward_cannot_be_used_by_shared_card_manager");f.cards->commit_use(*card);
    check(f.cards->inventory()[0].card_id==-1,"fortune_reward_use_not_committed");
    check(f.session->actor_begin(0,1,f.statuses[0]).duplicate,"same_turn_resumption_decremented_possession");
    for(std::uint64_t turn=2;turn<=6;++turn) {
        f.session->actor_begin(1,turn,f.statuses[1]);
        check(f.statuses[0].possession==3,"other_actor_turn_expired_fortune");
        const auto tick=f.session->actor_begin(0,turn,f.statuses[0]);
        check(tick.expired.has_value()==(turn==6),"fortune_wrong_own_turn_expiry");
    }
    check(!f.statuses[0].possession,"fortune_did_not_expire");
}
void money_wait_and_atomic_commit(const std::filesystem::path& root) {
    Fixture f(root);f.ground->place(114,{0,7,8});
    const auto before0=f.ledger->snapshot(0),before1=f.ledger->snapshot(1);
    const auto attached=f.session->landing(f.context(),0x4567,f.statuses[0]);
    check(attached && attached->messages==std::vector<Bytes>{{0x13,0x40,0x34,0x12,114,0}} &&
        attached->wait==RichonlineNpcWait::roulette34 && f.session->awaiting_roulette(),"wealth_did_not_wait_for34");
    check(f.ledger->snapshot(0)==before0 && f.ledger->snapshot(1)==before1,"money_moved_before_roulette");
    rejects([&]{f.session->actor_begin(1,2,f.statuses[1]);});
    rejects([&]{f.session->handle(Bytes{34,0,0x68,0x45,1,0xcc},0,f.statuses[0]);});
    check(f.session->awaiting_roulette() && f.ledger->snapshot(0)==before0,"bad_calendar_partially_committed");
    const auto result=f.session->handle(Bytes{34,0,0x67,0x45,1,0xcc},0,f.statuses[0]);
    check(result.messages==std::vector<Bytes>{{0x22,0x40,0x34,0x12,70,0,0}} && result.wait==RichonlineNpcWait::none &&
        result.continuation==RichonlineNpcContinuation::landing_phase1 && !result.sent_stop4013,"wealth_wrong_resume_phase");
    check(f.ledger->snapshot(0).funds.cash==170 && f.ledger->snapshot(1).funds.cash==0 &&
        f.ledger->snapshot(1).funds.deposit==70 && f.ledger->snapshot(0).revision==1 &&
        f.ledger->snapshot(1).revision==1,"wealth_not_committed_to_both_shared_balances");
    rejects([&]{f.session->handle(Bytes{34,0,0x67,0x45,1,0xcc},0,f.statuses[0]);});
    check(f.ledger->snapshot(0).funds.cash==170,"roulette_replay_debited_again");
    f.session->actor_begin(1,2,f.statuses[1]);
}
void failures_and_settlement(const std::filesystem::path& root) {
    Fixture f(root);f.policy.money_amount=[](std::uint8_t,std::int8_t,const auto&)->std::int16_t {throw CodecError("rng_failed");};f.reset();
    f.ground->place(114,{0,7,8});f.session->landing(f.context(),0x4567,f.statuses[0]);
    const auto before0=f.ledger->snapshot(0),before1=f.ledger->snapshot(1);
    rejects([&]{f.session->handle(Bytes{34,0,0x67,0x45,1,0xcc},0,f.statuses[0]);});
    check(f.session->awaiting_roulette() && f.ledger->snapshot(0)==before0 && f.ledger->snapshot(1)==before1,"failed_money_plan_mutated_shared_state");
    Fixture bankrupt(root,140);bankrupt.ground->place(114,{0,7,8});bankrupt.session->landing(bankrupt.context(),7,bankrupt.statuses[0]);
    const auto result=bankrupt.session->handle(Bytes{34,0,7,0,1,0xaa},0,bankrupt.statuses[0]);
    check(result.wait==RichonlineNpcWait::settlement && result.bankrupt_actor==1 && result.messages[0][6]==1 &&
        bankrupt.session->awaiting_settlement(),"depleted_donor_falsely_completed_landing");
    rejects([&]{bankrupt.session->finish_round(1);});
    Fixture invalid(root);invalid.statuses[0].possession=3;invalid.ground->place(114,{3,7,8});
    const auto ground=invalid.ground->snapshot();const auto inventory=invalid.cards->inventory();
    rejects([&]{invalid.session->landing(invalid.context(),7,invalid.statuses[0]);});
    check(invalid.ground->snapshot()==ground && invalid.cards->inventory()==inventory,"bad_clock_partially_consumed_ground");
}
void synthetic_money_is_server_driven(const std::filesystem::path& root) {
    Fixture f(root);f.ground->place(114,{0,7,8});
    const auto result=f.session->landing(f.context(1),7,f.statuses[1]);
    check(result && result->messages==std::vector<Bytes>{{0x13,0x40,0x34,0x12,114,0},{0x22,0x40,0x34,0x12,70,0,0}} &&
        result->wait==RichonlineNpcWait::none && !f.session->awaiting_roulette(),"synthetic_waited_for_local_only34");
    check(f.ledger->snapshot(0).funds.cash==30 && f.ledger->snapshot(1).funds.cash==110 &&
        f.statuses[1].possession==0 && f.ground->snapshot().objects.empty(),"synthetic_money_ground_state_not_committed");
    f.session->actor_begin(0,2,f.statuses[0]);
}
void unsupported_projected_landing_preserves_npc_transaction(const std::filesystem::path& root) {
    for(const auto npc : {0,3}) for(const auto actor : std::array<std::uint8_t,2>{0,1}) {
        Fixture f(root); f.ground->place(114,{static_cast<std::int8_t>(npc),7,8});
        const auto ground=f.ground->snapshot(); const auto inventory=f.cards->inventory();
        const auto before0=f.ledger->snapshot(0),before1=f.ledger->snapshot(1);
        bool projected=false;
        rejects([&] {f.session->landing(f.context(actor),7,f.statuses[actor],
            [&](const RichonlineLandingContext& after) {
                projected=after.actor_slot==actor && after.actor_status.possession==npc;
                throw CodecError("fixture_property_possession_unsupported");
            });});
        check(projected,"npc_preflight_did_not_receive_projected_possession");
        check(f.ground->snapshot()==ground && f.cards->inventory()==inventory &&
            f.ledger->snapshot(0)==before0 && f.ledger->snapshot(1)==before1 && !f.statuses[actor].possession &&
            !f.session->awaiting_roulette(),"rejected_continuation_partially_committed_npc");
        check(f.session->actor_begin(actor,1,f.statuses[actor]).duplicate,"rejected_continuation_changed_clock");
    }
}
void temple_clock_transactions(const std::filesystem::path& root) {
    for(const auto actor : std::array<std::uint8_t,2>{0,1}) {
        Fixture f(root,0);f.ground->place(114,{3,7,8});
        f.session->landing(f.context(actor),7,f.statuses[actor]);
        const auto before=f.statuses[actor];const auto inventory=f.cards->inventory();
        const auto funds0=f.ledger->snapshot(0),funds1=f.ledger->snapshot(1);const auto ground=f.ground->snapshot();
        auto plan=f.session->prepare_temple_change(actor,{before,false,1,10});
        check(f.statuses[actor]==before,"temple_prepare_mutated_status");
        check(f.session->commit_status_change(plan,f.statuses[actor]),"temple_duration_commit_failed");
        check(!f.session->commit_status_change(plan,f.statuses[actor]),"temple_duration_plan_replayed");
        check(f.session->actor_begin(actor,1,f.statuses[actor]).duplicate,"temple_lost_same_turn_identity");
        check(f.cards->inventory()==inventory && f.ground->snapshot()==ground &&
            f.ledger->snapshot(0)==funds0 && f.ledger->snapshot(1)==funds1,"temple_invented_wire_reward");
        check(!f.session->actor_begin(actor,2,f.statuses[actor]).expired,"temple_duration_expired_early");
        auto stale=f.session->prepare_temple_change(actor,{f.statuses[actor],false,0,10});
        check(!f.session->actor_begin(actor,3,f.statuses[actor]).expired,"temple_duration_expired_early");
        check(!f.session->commit_status_change(stale,f.statuses[actor]),"temple_plan_survived_clock_generation");
        check(f.session->actor_begin(actor,4,f.statuses[actor]).expired==3,"temple_reduced_clock_not_applied");

        Fixture extended(root,0);extended.ground->place(114,{1,7,8});
        extended.session->landing(extended.context(actor),7,extended.statuses[actor]);
        if(actor==0) {
            rejects([&]{extended.session->prepare_temple_change(actor,{extended.statuses[actor],true,2,6});});
            extended.session->resolve_roulette(actor,extended.statuses[actor]);
        }
        auto add=extended.session->prepare_temple_change(actor,{extended.statuses[actor],true,2,6});
        check(extended.session->commit_status_change(add,extended.statuses[actor]),"temple_extension_commit_failed");
        for(std::uint64_t turn=2;turn<=7;++turn)
            check(extended.session->actor_begin(actor,turn,extended.statuses[actor]).expired.has_value()==(turn==7),
                "temple_extension_or_maximum_wrong");

        Fixture detached(root);detached.ground->place(114,{3,7,8});
        detached.session->landing(detached.context(actor),7,detached.statuses[actor]);
        auto detach=detached.session->prepare_temple_change(actor,{detached.statuses[actor],false,-1,10});
        check(detached.session->commit_status_change(detach,detached.statuses[actor]) && !detached.statuses[actor].possession,
            "temple_immediate_detach_missing");
        check(!detached.session->actor_begin(actor,2,detached.statuses[actor]).expired,"temple_detached_clock_remained");
    }
}
void roulette_timeout_resolution(const std::filesystem::path& root) {
    Fixture f(root);f.ground->place(114,{0,7,8});
    f.session->landing(f.context(),7,f.statuses[0]);
    const auto before=f.ledger->snapshot(0);
    rejects([&]{f.session->resolve_roulette(1,f.statuses[1]);});
    check(f.ledger->snapshot(0)==before && f.session->awaiting_roulette(),"foreign_timeout_mutated_pending");
    const auto result=f.session->resolve_roulette(0,f.statuses[0]);
    check(result.messages==std::vector<Bytes>{{0x22,0x40,0x34,0x12,70,0,0}} &&
        result.continuation==RichonlineNpcContinuation::landing_phase1 && !f.session->awaiting_roulette(),
        "timeout_resolution_did_not_finish_authoritative_pending");
    const auto after=f.ledger->snapshot(0);
    rejects([&]{f.session->resolve_roulette(0,f.statuses[0]);});
    check(f.ledger->snapshot(0)==after,"timeout_resolution_replayed_transfer");
}
void card_and_replenishment(const std::filesystem::path& root) {
    Fixture f(root);auto inventory=f.cards->inventory();inventory[0]={1070,1};f.cards->commit_inventory(inventory);
    const auto result=f.session->fortune_card(Bytes{131,0,7,0,0,0},f.context(),f.statuses[0]);
    check(result.continuation==RichonlineNpcContinuation::restore_action && result.wait==RichonlineNpcWait::none &&
        !result.sent_stop4013 && result.messages[0]==Bytes({0xd3,0x40,0x34,0x12,0,0}),"fortune_card_not_restoring_action");
    check(f.cards->inventory()[0].card_id==1038 && f.cards->inventory()[1].card_id==1039,"fortune_card_consumption_and_rewards_not_shared");
    Fixture spawn(root);spawn.policy.spawn.initial_gods=3;spawn.policy.spawn.minimum_objects=2;
    spawn.session=std::make_unique<RichonlineNpcSession>(0x1234,"BS_1_1.emp",spawn.rules,spawn.resources,spawn.events,spawn.ledger,spawn.cards,spawn.ground,spawn.policy);
    check(spawn.session->initial().messages.size()==3,"closed_three_god_initial_policy_wrong");
    for(const auto& [position,object]:spawn.ground->snapshot().objects) {
        check(object.npc==0 || object.npc==1 || object.npc==3,"unclosed_god_spawned");
        spawn.ground->consume(position,object);
    }
    check(spawn.session->finish_round(1).messages.size()==2,"minimum_population_not_restored");
    check(spawn.session->finish_round(2).messages.empty() && spawn.session->finish_round(3).messages.size()==1,"third_round_refresh_wrong");
}
void summon_and_dismiss(const std::filesystem::path& root) {
    const auto first=[](std::size_t){return std::size_t{0};};
    const std::array<std::int16_t,1> visible{114};
    Fixture f(root);f.cards->commit_inventory(f.cards->prepare_add(1047));f.ground->place(114,{3,7,8});
    const auto result=f.session->deity_card(Bytes{112,0,7,0,0,0,0,0xef},f.context(),7,f.statuses[0],true,visible,first);
    check(result.messages==std::vector<Bytes>{{0xc0,0x40,0x34,0x12,0,0,114,0,0},{0x23,0x40,0x34,0x12,0x0e,4,0x0f,4}} &&
        result.continuation==RichonlineNpcContinuation::restore_action && result.wait==RichonlineNpcWait::none,
        "self_summon_fortune_sequence_incomplete");
    check(f.ground->snapshot().objects.empty() && f.statuses[0].possession==3 &&
        f.cards->inventory()[0].card_id==1038 && f.cards->inventory()[1].card_id==1039,"summon_consumption_must_precede_two_rewards");
    auto strength=f.session->prepare_temple_change(0,{f.statuses[0],true,0,10,{},20});
    check(f.session->commit_status_change(strength,f.statuses[0]),"dismiss_strength_setup_failed");
    f.cards->commit_inventory(f.cards->prepare_add(1048));
    const auto dismissed=f.session->deity_card(Bytes{113,0,7,0,2,0,0,0xef},f.context(),7,f.statuses[0],true,{},{});
    check(dismissed.messages==std::vector<Bytes>{{0xc1,0x40,0x34,0x12,2,0,0}} && !f.statuses[0].possession &&
        f.cards->inventory()[2].card_id==-1,"dismiss_did_not_consume_and_detach");
    check(f.statuses[0].possession_strength1740==0 && f.statuses[0].possession_multiplier1744==0.2F,
        "dismiss_card_left_positive_strength");
    f.session->actor_begin(0,2,f.statuses[0]);
    Fixture money(root);money.cards->commit_inventory(money.cards->prepare_add(1047));money.ground->place(114,{0,7,8});
    const auto pending=money.session->deity_card(Bytes{112,0,7,0,0,0,0,0},money.context(),7,money.statuses[0],true,visible,first);
    check(pending.wait==RichonlineNpcWait::roulette34 && pending.messages.size()==1,"summon_wealth_skipped_roulette");
    const auto paid=money.session->handle(Bytes{34,0,7,0,1,0},0,money.statuses[0]);
    check(paid.continuation==RichonlineNpcContinuation::restore_action && paid.wait==RichonlineNpcWait::none &&
        money.ledger->snapshot(0).funds.cash==170,"summon_wealth_wrong_resume_or_money");
    Fixture other(root);other.cards->commit_inventory(other.cards->prepare_add(1047));other.ground->place(114,{3,7,8});
    const auto target=other.session->deity_card(Bytes{112,0,7,0,0,0,1,0},other.context(),7,other.statuses[1],true,visible,first);
    check(target.messages==std::vector<Bytes>{{0xc0,0x40,0x34,0x12,0,0,114,0,1}} &&
        target.wait==RichonlineNpcWait::none && other.statuses[1].possession==3 && !other.statuses[0].possession &&
        other.cards->inventory()[0].card_id==-1,"other_target_summon_must_not_reward_source");
    other.session->actor_begin(1,2,other.statuses[1]);
}
void summon_rejection_preserves_state(const std::filesystem::path& root) {
    Fixture f(root);f.cards->commit_inventory(f.cards->prepare_add(1047));f.ground->place(114,{3,7,8});
    const auto inventory=f.cards->inventory();const auto ground=f.ground->snapshot();
    const std::array<std::int16_t,1> hidden{121},visible{114};const auto first=[](std::size_t){return std::size_t{0};};
    rejects([&]{f.session->deity_card(Bytes{112,0,7,0,0,0,0,0},f.context(),7,f.statuses[0],true,hidden,first);});
    rejects([&]{f.session->deity_card(Bytes{112,0,7,0,0,0,0,0},f.context(),8,f.statuses[0],true,visible,first);});
    rejects([&]{f.session->deity_card(Bytes{112,0,7,0,0,0,0,0},f.context(),7,f.statuses[0],false,visible,first);});
    rejects([&]{f.session->deity_card(Bytes{112,0,7,0,0,0,0,0},f.context(),7,f.statuses[0],true,visible,[](std::size_t n){return n;});});
    check(f.cards->inventory()==inventory && f.ground->snapshot()==ground && !f.statuses[0].possession,
        "invalid_summon_consumed_card_or_ground");
}
void badluck_ground_and_summon(const std::filesystem::path& root) {
    for(const auto origin:{RichonlineDeityMoneyOrigin::ground,RichonlineDeityMoneyOrigin::temple,
        RichonlineDeityMoneyOrigin::summoned_card}) {
        Fixture f(root);
        f.policy.badluck=RichonlineNpcBadluckPolicy{load_richonline_npc_affix(root,2),"fixture-half-units",
            [](const auto& inventory) {return select_richonline_badluck_half(inventory,4,
                [](std::size_t n){return n-1;});}};
        f.reset();RichonlineChanceInventory hand{};hand[2]={1038,1};hand[7]={1039,1};
        if(origin==RichonlineDeityMoneyOrigin::summoned_card) hand[0]={1047,1};
        f.cards->commit_inventory(hand);
        const Bytes loss{0x24,0x40,0x34,0x12,7,0xff,0xff,0xff};
        if(origin==RichonlineDeityMoneyOrigin::ground) {
            f.ground->place(114,{2,7,8});
            const auto result=f.session->landing(f.context(),7,f.statuses[0]);
            check(result && result->messages==std::vector<Bytes>{{0x13,0x40,0x34,0x12,114,0},loss},
                "half_badluck_ground_wire_wrong");
        } else if(origin==RichonlineDeityMoneyOrigin::temple) {
            check(f.session->temple_summon(f.context(),7,2,f.statuses[0]).messages==std::vector<Bytes>{loss},
                "half_badluck_temple_wire_wrong");
        } else {
            f.ground->place(114,{2,7,8});const std::array<std::int16_t,1> allowed{114};
            const auto result=f.session->deity_card(Bytes{112,0,7,0,0,0,0,0},f.context(),7,
                f.statuses[0],true,allowed,[](std::size_t){return std::size_t{0};});
            check(result.messages==std::vector<Bytes>{{0xc0,0x40,0x34,0x12,0,0,114,0,0},loss},
                "half_badluck_summon_wire_wrong");
        }
        check(f.cards->inventory()[2]==RichonlineChanceCardSlot{1038,1} &&
            f.cards->inventory()[7]==RichonlineChanceCardSlot{},"half_badluck_session_lost_both_cards");
    }
    const auto enable=[&](Fixture& f) {
        f.policy.badluck=RichonlineNpcBadluckPolicy{load_richonline_npc_affix(root,2),"fixture-first-slot",
            [](const auto& inventory) {
                for(std::size_t index=0;index<inventory.size();++index)
                    if(inventory[index].card_id!=-1) return std::array<std::int8_t,4>{static_cast<std::int8_t>(index),-1,-1,-1};
                return std::array<std::int8_t,4>{-1,-1,-1,-1};
            }};
        f.reset();
    };
    Fixture ground(root);enable(ground);
    ground.cards->commit_inventory(ground.cards->prepare_add(1038));ground.ground->place(114,{2,7,8});
    const auto picked=ground.session->landing(ground.context(),7,ground.statuses[0]);
    check(picked && picked->messages==std::vector<Bytes>{{0x13,0x40,0x34,0x12,114,0},
        {0x24,0x40,0x34,0x12,0,0xff,0xff,0xff}} && picked->wait==RichonlineNpcWait::none &&
        picked->continuation==RichonlineNpcContinuation::landing_phase1 && ground.statuses[0].possession==2 &&
        ground.cards->inventory()[0].card_id==-1,"ground_badluck_did_not_remove_card_and_continue");
    Fixture synthetic(root);enable(synthetic);
    synthetic.cards->commit_inventory(synthetic.cards->prepare_add(1038));synthetic.ground->place(114,{2,7,8});
    const auto saved=synthetic.cards->inventory();
    const auto boss=synthetic.session->landing(synthetic.context(1),7,synthetic.statuses[1]);
    check(boss && boss->messages==std::vector<Bytes>{{0x13,0x40,0x34,0x12,114,0}} &&
        synthetic.cards->inventory()==saved && synthetic.statuses[1].possession==2,
        "synthetic_badluck_removed_local_inventory");
    Fixture summoned(root);enable(summoned);
    summoned.cards->commit_inventory(summoned.cards->prepare_add(1047));
    summoned.cards->commit_inventory(summoned.cards->prepare_add(1038));summoned.ground->place(114,{2,7,8});
    const std::array<std::int16_t,1> allowed{114};
    const auto result=summoned.session->deity_card(Bytes{112,0,7,0,0,0,0,0},summoned.context(),7,
        summoned.statuses[0],true,allowed,[](std::size_t){return std::size_t{0};});
    check(result.messages==std::vector<Bytes>{{0xc0,0x40,0x34,0x12,0,0,114,0,0},
        {0x24,0x40,0x34,0x12,1,0xff,0xff,0xff}} && result.continuation==RichonlineNpcContinuation::restore_action &&
        summoned.cards->inventory()[0].card_id==-1 && summoned.cards->inventory()[1].card_id==-1,
        "summoned_badluck_did_not_apply_after_consumption");
    Fixture failed(root);enable(failed);
    failed.policy.badluck->lost_slots=[](const auto&){return std::array<std::int8_t,4>{0,-1,-1,-1};};failed.reset();
    failed.ground->place(114,{2,7,8});
    const auto before_ground=failed.ground->snapshot();const auto before_cards=failed.cards->inventory();
    rejects([&]{failed.session->landing(failed.context(),7,failed.statuses[0]);});
    check(failed.ground->snapshot()==before_ground && failed.cards->inventory()==before_cards && !failed.statuses[0].possession,
        "invalid_badluck_policy_partially_committed");
}
void ticket_chest_shared_balance(const std::filesystem::path& root) {
    Fixture f(root);f.policy.ticket_chest=RichonlineTicketChestRules::load(root);f.reset();
    const auto before=f.ledger->snapshot(0);f.ground->place(114,{9,7,8});
    const auto result=f.session->landing(f.context(),7,f.statuses[0]);
    check(result && result->messages==std::vector<Bytes>{{0x13,0x40,0x34,0x12,114,0}} &&
        result->continuation==RichonlineNpcContinuation::landing_phase1 && result->wait==RichonlineNpcWait::none,
        "chest_sent_duplicate_funds_packet_or_skipped_landing");
    auto expected=before.funds;expected.tickets+=f.policy.ticket_chest->tickets;
    check(f.ledger->snapshot(0).funds==expected && f.ledger->snapshot(0).revision==before.revision+1 &&
        f.ground->snapshot().objects.empty() && !f.statuses[0].possession,"chest_did_not_commit_shared_ticket_balance");
    const auto paid=f.ledger->snapshot(0);
    check(!f.session->landing(f.context(),7,f.statuses[0]) && f.ledger->snapshot(0)==paid,"chest_replay_credited_twice");
    f.ground->place(114,{9,7,8});const auto boss_before=f.ledger->snapshot(1);
    const auto boss=f.session->landing(f.context(1),7,f.statuses[1]);
    check(boss && f.ground->snapshot().objects.empty() && f.ledger->snapshot(1)==boss_before &&
        f.ledger->snapshot(0)==paid,"boss_chest_changed_balance_or_left_object");
    f.ground->place(114,{9,7,8});f.statuses[0].frozen=2;
    const auto frozen=f.session->landing(f.context(),7,f.statuses[0]);
    check(frozen.has_value() && f.ground->snapshot().objects.empty() &&
        f.ledger->snapshot(0).funds.tickets==paid.funds.tickets+f.policy.ticket_chest->tickets,
        "frozen_actor_did_not_follow_real_chest_ground_branch");
    f.ground->place(114,{9,7,8});f.statuses[0].sleepwalking=2;
    const auto sleeping_ground=f.ground->snapshot();const auto sleeping_funds=f.ledger->snapshot(0);
    check(!f.session->landing(f.context(),7,f.statuses[0]) && f.ground->snapshot()==sleeping_ground &&
        f.ledger->snapshot(0)==sleeping_funds,"sleepwalking_actor_consumed_chest");
    Fixture spawn(root);spawn.policy.ticket_chest=RichonlineTicketChestRules::load(root);
    spawn.policy.spawn.initial_chests=1;spawn.policy.spawn.refresh_chests=true;
    spawn.session=std::make_unique<RichonlineNpcSession>(0x1234,"BS_1_1.emp",spawn.rules,spawn.resources,
        spawn.events,spawn.ledger,spawn.cards,spawn.ground,spawn.policy);
    const auto initial=spawn.session->initial();
    check(initial.messages.size()==1 && spawn.ground->snapshot().objects.begin()->second.npc==9,
        "configured_chest_population_not_enabled");
}
void sleep_deity_protection_and_ownership(const std::filesystem::path& root) {
    const auto enable=[&](Fixture& f) {
        f.policy.sleep_deity=RichonlineNpcSleepPolicy{load_richonline_npc_affix(root,7),"fixture-no-equipment",
            [resources=f.resources](std::uint8_t actor,const auto& inventory,const auto& status) {
                return resolve_richonline_sleep_protection("BS_1_1.emp",*resources,
                    {actor,actor,inventory,std::nullopt,false},status).main_inventory_projection();
            }};
        f.reset();
    };
    Fixture f(root);enable(f);f.ground->place(114,{7,0xff,0xff});
    const auto result=f.session->landing(f.context(),7,f.statuses[0]);
    check(result && result->messages==std::vector<Bytes>{{0x13,0x40,0x34,0x12,114,0}} &&
        f.statuses[0].possession==7 && f.statuses[0].sleepwalking==0 && !f.session->awaiting_roulette(),
        "sleep_deity_created_fake_counter_or_wait");
    for(std::uint64_t turn=2;turn<=4;++turn) {
        const auto tick=f.session->actor_begin(0,turn,f.statuses[0]);
        check(tick.expired.has_value()==(turn==4),"sleep_deity_did_not_use_real_three_turn_affix");
    }
    Fixture immunity(root);enable(immunity);immunity.statuses[0].protected_from_status=true;
    immunity.cards->commit_inventory(immunity.cards->prepare_add(1071));immunity.ground->place(114,{7,0xff,0xff});
    const auto untouched=immunity.cards->inventory();
    check(immunity.session->landing(immunity.context(),7,immunity.statuses[0]).has_value() &&
        !immunity.statuses[0].possession && immunity.cards->inventory()==untouched,"innate_immunity_consumed1071");
    immunity.session->actor_begin(0,2,immunity.statuses[0]);
    Fixture protected_player(root);enable(protected_player);
    protected_player.cards->commit_inventory(protected_player.cards->prepare_add(1071));
    protected_player.ground->place(114,{7,0xff,0xff});
    check(protected_player.session->landing(protected_player.context(),7,protected_player.statuses[0]).has_value() &&
        !protected_player.statuses[0].possession && protected_player.cards->inventory()[0].card_id==-1,
        "main1071_was_not_consumed_to_detach_sleep_deity");
    protected_player.session->actor_begin(0,2,protected_player.statuses[0]);
    Fixture boss(root);enable(boss);boss.cards->commit_inventory(boss.cards->prepare_add(1071));boss.ground->place(114,{7,0xff,0xff});
    const auto player_cards=boss.cards->inventory();
    check(boss.session->landing(boss.context(1),7,boss.statuses[1]).has_value() && boss.statuses[1].possession==7 &&
        boss.cards->inventory()==player_cards,"boss_sleep_protection_consumed_human_card");
    Fixture summon(root);enable(summon);summon.cards->commit_inventory(summon.cards->prepare_add(1047));
    summon.cards->commit_inventory(summon.cards->prepare_add(1071));summon.ground->place(114,{7,0xff,0xff});
    const std::array<std::int16_t,1> allowed{114};
    const auto summoned=summon.session->deity_card(Bytes{112,0,7,0,0,0,0,0},summon.context(),7,summon.statuses[0],true,
        allowed,[](std::size_t){return std::size_t{0};});
    check(summoned.messages==std::vector<Bytes>{{0xc0,0x40,0x34,0x12,0,0,114,0,0}} && !summon.statuses[0].possession &&
        summon.cards->inventory()[0].card_id==-1 && summon.cards->inventory()[1].card_id==-1 &&
        summoned.continuation==RichonlineNpcContinuation::restore_action,"self_summon_sleep_protection_incomplete");
    Fixture other(root);enable(other);other.cards->commit_inventory(other.cards->prepare_add(1047));
    other.cards->commit_inventory(other.cards->prepare_add(1071));other.ground->place(114,{7,0xff,0xff});
    const auto target=other.session->deity_card(Bytes{112,0,7,0,0,0,1,0},other.context(),7,other.statuses[1],true,
        allowed,[](std::size_t){return std::size_t{0};});
    check(target.wait==RichonlineNpcWait::none && other.statuses[1].possession==7 &&
        other.cards->inventory()[0].card_id==-1 && other.cards->inventory()[1].card_id==1071,
        "other_actor_sleep_summon_used_wrong_inventory");
}
void temple_aura_attachment(const std::filesystem::path& root) {
    for(const std::int8_t npc:{std::int8_t{4},std::int8_t{6}}) {
        Fixture f(root);
        const RichonlineTemplePossessionChange change{f.statuses[0],false,0,10,npc};
        rejects([&]{f.session->prepare_temple_change(0,change);});
        f.policy.temple_aura_affix=std::array<std::uint8_t,2>{3,5};f.reset();
        f.ground->place(114,{npc,0xff,0xff});const auto ground=f.ground->snapshot();
        check(!f.session->landing(f.context(),7,f.statuses[0]) && f.ground->snapshot().objects==ground.objects,
            "temple_capability_enabled_ground_roulette");
        auto stale=f.session->prepare_temple_change(0,change);
        f.session->actor_begin(0,2,f.statuses[0]);
        check(!f.session->commit_status_change(stale,f.statuses[0]),"temple_summon_survived_clock_generation_change");
        auto attach=f.session->prepare_temple_change(0,change);auto copied=attach;
        check(f.session->commit_status_change(attach,f.statuses[0]) && f.statuses[0].possession==npc,
            "temple_summon_did_not_attach");
        check(!f.session->commit_status_change(copied,f.statuses[0]),"temple_summon_replayed");
        check(f.session->actor_begin(0,2,f.statuses[0]).duplicate,"temple_summon_reset_own_turn_identity");
        rejects([&]{f.session->prepare_temple_change(0,{f.statuses[0],false,0,10,npc});});
        auto duration=f.session->prepare_temple_change(0,{f.statuses[0],true,2,10});
        check(f.session->commit_status_change(duration,f.statuses[0]),"aura_duration_extension_rejected");
        const auto turns=npc==4?5U:7U;
        for(unsigned i=1;i<=turns;++i)
            check(f.session->actor_begin(0,2+i,f.statuses[0]).expired.has_value()==(i==turns),
                "temple_summon_affix_or_expiry_wrong");
        check(f.ledger->snapshot(0).funds.cash==100 && f.cards->inventory()==RichonlineChanceInventory{} &&
            f.ground->snapshot().objects==ground.objects,"temple_summon_changed_unrelated_state");
        Fixture invalid(root);invalid.policy.temple_aura_affix=std::array<std::uint8_t,2>{0,3};
        rejects([&]{invalid.reset();});
    }
}
void higher_temple_summon_transactions(const std::filesystem::path& root) {
    for(const auto actor:std::array<std::uint8_t,2>{0,1}) for(const auto npc:std::array<std::int8_t,4>{0,1,2,3}) {
        Fixture f(root,0);
        f.policy.badluck=RichonlineNpcBadluckPolicy{load_richonline_npc_affix(root,2),"fixture-first-slot",
            [](const auto&) {return std::array<std::int8_t,4>{0,-1,-1,-1};}};
        f.reset();f.cards->commit_inventory(f.cards->prepare_add(1038));f.ground->place(114,{3,7,8});
        const auto ground=f.ground->snapshot();const auto cards=f.cards->inventory();
        const auto funds0=f.ledger->snapshot(0),funds1=f.ledger->snapshot(1);
        const auto result=f.session->temple_summon(f.context(actor),7,npc,f.statuses[actor]);
        check(!result.sent_stop4013 && result.continuation==RichonlineNpcContinuation::landing_phase6 &&
            f.statuses[actor].possession==npc && f.ground->snapshot()==ground,"temple_summon_repeated_stop_or_consumed_ground");
        if(npc<=1 && actor==0) {
            check(result.messages.empty() && result.wait==RichonlineNpcWait::roulette34,"temple_money_skipped_local_roulette");
            rejects([&]{f.session->handle(Bytes{34,0,8,0,1,0},actor,f.statuses[actor]);});
            rejects([&]{f.session->resolve_roulette(1,f.statuses[1]);});
            const auto paid=f.session->handle(Bytes{34,0,7,0,1,0},actor,f.statuses[actor]);
            check(paid.continuation==RichonlineNpcContinuation::landing_phase6 && paid.messages==
                std::vector<Bytes>{{0x22,0x40,0x34,0x12,0,0,0}},"temple_roulette_resumed_wrong_phase");
            rejects([&]{f.session->handle(Bytes{34,0,7,0,1,0},actor,f.statuses[actor]);});
        } else {
            check(result.wait==RichonlineNpcWait::none,"temple_immediate_summon_waited");
            const std::vector<Bytes> expected=npc<=1?std::vector<Bytes>{{0x22,0x40,0x34,0x12,0,0,0}}:
                actor==1?std::vector<Bytes>{}:npc==2?std::vector<Bytes>{{0x24,0x40,0x34,0x12,0,0xff,0xff,0xff}}:
                std::vector<Bytes>{{0x23,0x40,0x34,0x12,0x0e,4,0x0f,4}};
            check(result.messages==expected,"temple_summon_wire_wrong");
        }
        if(actor==0 && npc==2) check(f.cards->inventory()[0].card_id==-1,"temple_badluck_did_not_remove_card");
        else if(actor==0 && npc==3) check(f.cards->inventory()!=cards,"temple_fortune_did_not_reward");
        else check(f.cards->inventory()==cards,"temple_boss_changed_human_inventory");
        check(f.ledger->snapshot(0).funds==funds0.funds && f.ledger->snapshot(1).funds==funds1.funds,
            "zero_transfer_temple_changed_money");
        rejects([&]{f.session->temple_summon(f.context(actor),7,npc,f.statuses[actor]);});
        check(f.session->actor_begin(actor,1,f.statuses[actor]).duplicate,"temple_summon_reset_turn_identity");
        const auto turns=load_richonline_npc_affix(root,npc);
        for(unsigned next=1;next<=turns;++next)
            check(f.session->actor_begin(actor,1+next,f.statuses[actor]).expired.has_value()==(next==turns),
                "temple_summon_expiry_wrong");
    }
    Fixture failed(root);
    failed.policy.money_amount=[](std::uint8_t,std::int8_t,const auto&)->std::int16_t {throw CodecError("fixture_money_failure");};
    failed.reset();const auto inventory=failed.cards->inventory();const auto ground=failed.ground->snapshot();
    const auto funds=failed.ledger->snapshot(0);
    rejects([&]{failed.session->temple_summon(failed.context(1),7,0,failed.statuses[1]);});
    check(!failed.statuses[1].possession && failed.cards->inventory()==inventory && failed.ground->snapshot()==ground &&
        failed.ledger->snapshot(0)==funds && failed.session->actor_begin(1,1,failed.statuses[1]).duplicate,
        "temple_failed_money_plan_committed_state");
    failed.session->temple_summon(failed.context(),7,0,failed.statuses[0]);
    rejects([&]{failed.session->resolve_roulette(0,failed.statuses[0]);});
    check(failed.session->awaiting_roulette() && failed.ledger->snapshot(0)==funds,"temple_failed_roulette_lost_pending");
    Fixture timeout(root,0);timeout.session->temple_summon(timeout.context(),7,1,timeout.statuses[0]);
    check(timeout.session->resolve_roulette(0,timeout.statuses[0]).continuation==RichonlineNpcContinuation::landing_phase6,
        "temple_timeout_resumed_wrong_phase");
    Fixture bankrupt(root,140);bankrupt.session->temple_summon(bankrupt.context(),7,0,bankrupt.statuses[0]);
    const auto settlement=bankrupt.session->resolve_roulette(0,bankrupt.statuses[0]);
    check(settlement.wait==RichonlineNpcWait::settlement && settlement.bankrupt_actor==1 &&
        bankrupt.session->awaiting_settlement(),"temple_depleted_donor_skipped_settlement");
}
void external_status_change_and_detach(const std::filesystem::path& root) {
    Fixture kept(root);kept.ground->place(114,{3,0xff,0xff});
    kept.session->landing(kept.context(),7,kept.statuses[0]);
    const auto before=kept.statuses[0];auto updated=before;updated.turtle=2;
    auto plan=kept.session->prepare_status_change(0,before,updated);auto copied=plan;
    check(kept.session->matches_status_change(plan,kept.statuses[0]) &&
        kept.session->commit_status_change(plan,kept.statuses[0]) && kept.statuses[0]==updated,
        "external_motion_status_was_not_committed_with_clock");
    check(!kept.session->commit_status_change(plan,kept.statuses[0]) &&
        !kept.session->commit_status_change(copied,kept.statuses[0]),"status_plan_was_committed_twice");
    for(std::uint64_t turn=2;turn<=6;++turn)
        check(kept.session->actor_begin(0,turn,kept.statuses[0]).expired.has_value()==(turn==6),
            "external_unrelated_status_reset_possession_duration");
    Fixture detached(root);detached.ground->place(114,{3,0xff,0xff});
    detached.session->landing(detached.context(),7,detached.statuses[0]);
    const auto cards=detached.cards->inventory();const auto funds=detached.ledger->snapshot(0);
    auto control=detached.statuses[0];control.possession.reset();control.sleepwalking=3;
    auto changed=detached.session->prepare_status_change(0,detached.statuses[0],control);
    check(detached.session->commit_status_change(changed,detached.statuses[0]) && detached.statuses[0]==control,
        "external_control_detach_did_not_update_authoritative_status");
    check(detached.session->actor_begin(0,1,detached.statuses[0]).duplicate,
        "external_detach_lost_current_turn_identity");
    detached.session->actor_begin(0,2,detached.statuses[0]);
    check(!detached.statuses[0].possession && detached.cards->inventory()==cards && detached.ledger->snapshot(0)==funds,
        "detach_changed_unrelated_inventory_or_funds");
    Fixture foreign(root);foreign.ground->place(114,{3,0xff,0xff});
    foreign.session->landing(foreign.context(),7,foreign.statuses[0]);
    auto foreign_after=foreign.statuses[0];foreign_after.possession.reset();
    auto foreign_plan=foreign.session->prepare_status_change(0,foreign.statuses[0],foreign_after);
    check(!detached.session->commit_status_change(foreign_plan,detached.statuses[0]),"foreign_session_status_plan_accepted");
    auto forbidden=foreign.statuses[0];forbidden.possession=1;
    rejects([&]{foreign.session->prepare_status_change(0,foreign.statuses[0],forbidden);});
    foreign.session->detach(0,foreign.statuses[0]);foreign.session->actor_begin(0,2,foreign.statuses[0]);
    check(!foreign.statuses[0].possession,"convenience_detach_left_clock_attached");
    Fixture stale(root);stale.ground->place(114,{3,0xff,0xff});stale.session->landing(stale.context(),7,stale.statuses[0]);
    auto stale_after=stale.statuses[0];stale_after.possession.reset();
    auto stale_plan=stale.session->prepare_status_change(0,stale.statuses[0],stale_after);
    stale.session->actor_begin(0,2,stale.statuses[0]);
    check(!stale.session->commit_status_change(stale_plan,stale.statuses[0]) && stale.statuses[0].possession==3,
        "plan_survived_own_turn_clock_change");
    auto aba=stale.session->prepare_status_change(0,stale.statuses[0],stale_after);
    stale.ground->place(114,{3,0xff,0xff});stale.session->landing(stale.context(),7,stale.statuses[0]);
    check(!stale.session->commit_status_change(aba,stale.statuses[0]),"plan_detached_replacement_possession");
    Fixture pending(root);pending.ground->place(114,{0,0xff,0xff});pending.session->landing(pending.context(),7,pending.statuses[0]);
    const auto pending_before=pending.statuses[0];const auto pending_funds=pending.ledger->snapshot(0);
    rejects([&]{pending.session->detach(0,pending.statuses[0]);});
    check(pending.statuses[0]==pending_before && pending.ledger->snapshot(0)==pending_funds &&
        pending.session->awaiting_roulette(),"pending_money_detach_discarded_transaction");
    pending.session->resolve_roulette(0,pending.statuses[0]);pending.session->detach(0,pending.statuses[0]);
    pending.session->actor_begin(0,2,pending.statuses[0]);
}
void temple_strength_lifecycle(const std::filesystem::path& root) {
    for(const auto npc:std::array<std::int8_t,7>{0,1,2,3,4,6,7}) {
        RichonlineActorStatus status;status.possession=npc;
        richonline_set_possession_strength(status,20);
        const float expected=npc==4 || npc==6 ? 1.2F : npc==7 ? 0.0F : 0.2F;
        check(status.possession_strength1740==20 && status.possession_multiplier1744==expected,
            "strength_setter_wrong_NPC_formula");
        richonline_detach_possession(status);
        check(!status.possession && status.possession_strength1740==0 && status.possession_multiplier1744==expected,
            "detach_did_not_clear_only_positive_strength");
        status.possession=3;richonline_set_possession_strength(status,-20);richonline_detach_possession(status);
        check(status.possession_strength1740==-20 && status.possession_multiplier1744==-0.2F,
            "detach_cleared_nonpositive_strength");
    }
    Fixture f(root);f.policy.temple_aura_affix=std::array<std::uint8_t,2>{3,5};f.reset();
    auto attach=f.session->prepare_temple_change(0,{f.statuses[0],false,0,10,4});
    check(f.session->commit_status_change(attach,f.statuses[0]),"strength_aura_attach_failed");
    auto change=RichonlineTemplePossessionChange{f.statuses[0],true,0,10,{},20};
    auto plan=f.session->prepare_temple_change(0,change);auto copied=plan;
    check(f.statuses[0].possession_strength1740==0,"strength_mutated_before_commit");
    check(f.session->commit_status_change(plan,f.statuses[0]) && f.statuses[0].possession_multiplier1744==1.2F,
        "strength_not_committed_with_clock");
    auto forbidden=f.statuses[0];forbidden.possession_strength1740=10;
    rejects([&]{f.session->prepare_status_change(0,f.statuses[0],forbidden);});
    forbidden=f.statuses[0];forbidden.possession_multiplier1744=0.1F;
    rejects([&]{f.session->prepare_status_change(0,f.statuses[0],forbidden);});
    check(!f.session->commit_status_change(copied,f.statuses[0]),"strength_plan_replayed");
    f.ground->place(114,{3,7,8});f.session->landing(f.context(),7,f.statuses[0]);
    check(f.statuses[0].possession==3 && f.statuses[0].possession_strength1740==20 &&
        f.statuses[0].possession_multiplier1744==1.2F,"replacement_attachment_reset_strength");
    auto stale=f.session->prepare_temple_change(0,{f.statuses[0],true,0,10,{},10});
    f.session->actor_begin(0,2,f.statuses[0]);
    check(!f.session->commit_status_change(stale,f.statuses[0]) && f.statuses[0].possession_multiplier1744==1.2F,
        "strength_plan_survived_clock_generation_change");
    auto replace=f.session->prepare_temple_change(0,{f.statuses[0],true,0,10,{},10});
    check(f.session->commit_status_change(replace,f.statuses[0]) && f.statuses[0].possession_strength1740==10 &&
        f.statuses[0].possession_multiplier1744==0.1F,"strength_accumulated_instead_of_overwritten");
    auto unchanged=f.session->prepare_temple_change(0,{f.statuses[0],true,0,10,{},-1});
    const auto before=f.statuses[0];
    check(f.session->commit_status_change(unchanged,f.statuses[0]) && f.statuses[0]==before,
        "nonpositive_temple_effect_reset_strength");
    for(std::uint64_t turn=3;turn<=6;++turn) f.session->actor_begin(0,turn,f.statuses[0]);
    check(!f.statuses[0].possession && f.statuses[0].possession_strength1740==0 &&
        f.statuses[0].possession_multiplier1744==0.1F,"strength_survived_possession_expiry");
    f.ground->place(114,{3,7,8});f.session->landing(f.context(),7,f.statuses[0]);
    auto strengthen=f.session->prepare_temple_change(0,{f.statuses[0],true,0,10,{},20});
    check(f.session->commit_status_change(strengthen,f.statuses[0]),"detach_strength_setup_failed");
    auto detached=f.statuses[0];detached.possession.reset();
    auto detach=f.session->prepare_status_change(0,f.statuses[0],detached);
    check(f.session->commit_status_change(detach,f.statuses[0]) && f.statuses[0].possession_strength1740==0 &&
        f.statuses[0].possession_multiplier1744==0.2F,"external_detach_left_strength_active");
}
}
int main(int argc,char** argv) {
    try {check(argc==2,"NEW_resource_root_required");const std::filesystem::path root(argv[1]);
        fortune_lifecycle(root);money_wait_and_atomic_commit(root);failures_and_settlement(root);card_and_replenishment(root);
        synthetic_money_is_server_driven(root);roulette_timeout_resolution(root);
        unsupported_projected_landing_preserves_npc_transaction(root);
        temple_clock_transactions(root);
        summon_and_dismiss(root);summon_rejection_preserves_state(root);badluck_ground_and_summon(root);
        ticket_chest_shared_balance(root);
        sleep_deity_protection_and_ownership(root);
        external_status_change_and_detach(root);
        temple_aura_attachment(root);
        higher_temple_summon_transactions(root);
        temple_strength_lifecycle(root);
        std::cout<<"PASS NEW production NPC hooks: shared cards/funds/status, phase continuations, roulette waits, own-turn expiry and closed spawning\n";
    }catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
