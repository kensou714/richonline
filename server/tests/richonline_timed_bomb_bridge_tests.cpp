#include "richonline_combat_bridge.hpp"
#include "richonline_boss_stage.hpp"
#include <iostream>

namespace {
using namespace richnet;
constexpr auto policy=RichonlineTimedBombContinuationPolicy::timed_bomb_stop_then_landing;
void check(bool ok,const char* why) { if(!ok) throw std::runtime_error(why); }
void rejects(auto action,const char* code) {
    try { action(); } catch(const CodecError& error) { check(std::string(error.what())==code,error.what());return; }
    throw std::runtime_error("expected_timed_bomb_bridge_rejection");
}
RichonlineTimedBombEligibility raw() {
    RichonlineTimedBombEligibility result;
    result[0]=RichonlineTimedBombRawEligibility{-1,-1,-1,-1};
    result[1]=RichonlineTimedBombRawEligibility{-1,-1,-1,-1};return result;
}
struct Fixture {
    std::shared_ptr<RichonlineGameLedger> ledger=std::make_shared<RichonlineGameLedger>(
        std::vector<RichonlineGameFunds>{{10000,1000,100,{}},{100000,1000,100,{}}});
    std::shared_ptr<RichonlineBossCards> cards;
    std::shared_ptr<RichonlineBossProperty> property;
    std::shared_ptr<RichonlineGroundObjects> ground;
    RichonlineCombatWorld world;
    std::array<RichonlineActorStatus,2> statuses{};
    std::array<bool,2> active{true,true};
    std::array<RichonlineCombatActorRef,2> refs;
    explicit Fixture(const std::filesystem::path& root):refs{{{0,232,&statuses[0],{true,false,false,false,true},&active[0]},
        {1,231,&statuses[1],{true,false,false,false,true},&active[1]}}} {
        const auto stage=load_richonline_boss_stage(root,"BS_1_1.emp");
        cards=std::make_shared<RichonlineBossCards>(std::make_shared<const RichonlineChanceResources>(
            RichonlineChanceResources::load(root)),7,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0,0}});
        property=std::make_shared<RichonlineBossProperty>(root,7,ledger,stage);
        const auto topology=load_richonline_road_topology(root/"Map/BS_1_1.emp");
        std::vector<std::int16_t> roads;
        for(const auto& cell:topology.cells()) if(cell.walkable) roads.push_back(cell.position);
        ground=std::make_shared<RichonlineGroundObjects>(std::move(roads));
        world.width=static_cast<std::uint16_t>(topology.width());world.height=static_cast<std::uint16_t>(topology.height());
        world.resources={3000,4000,5000,1000,1500,3,2,1,2,2};
        world.step=[](std::int16_t,std::uint8_t)->std::optional<std::int16_t>{return {};};
        world.targets=[](std::uint8_t,RichonlineCombatEffect,const RichonlineCombatSessionView&) {
            return std::vector<std::int16_t>{232};
        };
        world.resolve_terms=[](const RichonlineCombatActorView&,const RichonlineCombatSessionView&) {
            return RichonlineCombatWorld::ResolvedTerms{{},{},0,0};
        };
        world.building=[property=property](const RichonlineCombatBuildingView& before,RichonlineBossBlastBuildingEffect effect) {
            return property->combat_building_effect(before,effect);
        };
    }
    RichonlineCombatBridge bridge() {return {7,ledger,cards,ground,property,world,{}};}
};
void attachment_commits_same_hand_and_status(const std::filesystem::path& root) {
    Fixture fixture(root);auto bridge=fixture.bridge();auto eligibility=raw();
    RichonlineChanceInventory hand{};hand[3]={1045,2};hand[5]={1076,1};fixture.cards->commit_inventory(hand);
    fixture.statuses[1].protected_from_status=true;fixture.statuses[1].safety_helmet_uses=9;
    const auto money=fixture.ledger->snapshot(0).funds;
    const auto attached=bridge.timed_bomb_card(fixture.refs,0,{9,3,0,1,0xcd},9,
        RichonlineTimedBombRules::load(root),eligibility,0xab);
    hand[3].count=1;
    check(attached.packets==std::vector<Bytes>{{0xbe,0x40,7,0,3,0,1,0xab}} && fixture.cards->inventory()==hand &&
        fixture.statuses[1].timed_bomb==36 && fixture.statuses[1].timed_bomb_owner==0 &&
        fixture.statuses[1].protected_from_status && fixture.statuses[1].safety_helmet_uses==9 &&
        fixture.ledger->snapshot(0).funds==money,"shared_attachment_inventory_owner_or_counter_wrong");
    const auto funds=fixture.ledger->snapshot(0);const auto ground=fixture.ground->snapshot();
    eligibility[1]->actor1494=0;
    rejects([&]{bridge.timed_bomb_card(fixture.refs,0,{9,3,0,1,0xcd},9,{36},eligibility,0);},
        "richonline_timed_bomb_target_not_authorized");
    check(fixture.cards->inventory()==hand && fixture.ledger->snapshot(0)==funds && fixture.ground->snapshot()==ground &&
        fixture.statuses[1].timed_bomb==36,"failed_attachment_partially_committed");
    rejects([&]{bridge.timed_bomb_card(fixture.refs,1,{9,3,0,1,0},9,{36},raw(),0);},
        "richonline_timed_bomb_bridge_inventory_actor_invalid");
}
void explosion_confirmation_is_atomic_and_one_use(const std::filesystem::path& root) {
    Fixture fixture(root);fixture.statuses[0].timed_bomb=1;fixture.statuses[0].timed_bomb_owner=1;
    fixture.statuses[0].safety_helmet_uses=12;
    RichonlineChanceInventory hand{};hand[5]={1076,1};fixture.cards->commit_inventory(hand);
    fixture.ground->place(232,{11,255,255});auto bridge=fixture.bridge();
    const auto funds=fixture.ledger->snapshot(0);const auto ground=fixture.ground->snapshot();
    const RichonlineTimedBombStepContext step{0,2,232,true,false,raw()};
    rejects([&]{bridge.timed_bomb_step(fixture.refs,step,{},9,policy);},"richonline_timed_bomb_explosion_ack_missing");
    rejects([&]{bridge.timed_bomb_step(fixture.refs,step,RichonlineMoveCountdown12{8,232},9,policy);},
        "richonline_timed_bomb_ack_calendar_mismatch");
    rejects([&]{bridge.timed_bomb_step(fixture.refs,step,RichonlineMoveCountdown12{9,231},9,policy);},
        "richonline_timed_bomb_ack_position_mismatch");
    check(fixture.ledger->snapshot(0)==funds && fixture.ground->snapshot()==ground && fixture.statuses[0].timed_bomb==1 &&
        fixture.cards->inventory()==hand,"failed_ack_changed_world_or_funds");
    const auto exploded=bridge.timed_bomb_step(fixture.refs,step,RichonlineMoveCountdown12{9,232},9,policy);
    check(exploded.packets==std::vector<Bytes>{{0x13,0x40,7,0,232,0}} && exploded.bankrupt_actors.empty() &&
        !fixture.statuses[0].timed_bomb && !fixture.statuses[0].timed_bomb_owner &&
        fixture.statuses[0].safety_helmet_uses==12 && fixture.cards->inventory()==hand &&
        fixture.ledger->snapshot(0).funds.cash==6000 && fixture.ground->snapshot().objects.empty(),
        "shared_explosion_not_mirrored_once");
    const auto settled=fixture.ledger->snapshot(0);const auto cleared=fixture.ground->snapshot();
    rejects([&]{bridge.timed_bomb_step(fixture.refs,step,RichonlineMoveCountdown12{9,232},9,policy);},
        "richonline_timed_bomb_ack_without_explosion");
    check(fixture.ledger->snapshot(0)==settled && fixture.ground->snapshot()==cleared,"duplicate12_damaged_twice");
    check(bridge.timed_bomb_step(fixture.refs,step,{},9,policy).packets.empty() && fixture.ledger->snapshot(0)==settled,
        "no_bomb_step_mutated_authority");
}
void stale_plan_and_terminal_share_same_authority(const std::filesystem::path& root) {
    Fixture fixture(root);fixture.statuses[0].timed_bomb=1;fixture.statuses[0].timed_bomb_owner=-1;
    fixture.ground->place(232,{30,255,255});const auto funds=fixture.ledger->snapshot(0);
    const auto ground=fixture.ground->snapshot();
    fixture.world.resolve_terms=[&](const auto&,const auto&) {
        fixture.statuses[0].stay=1;return RichonlineCombatWorld::ResolvedTerms{{},{},0,0};
    };
    auto stale=fixture.bridge();const RichonlineTimedBombStepContext step{0,2,232,true,false,raw()};
    rejects([&]{stale.timed_bomb_step(fixture.refs,step,RichonlineMoveCountdown12{9,232},9,policy);},
        "richonline_combat_bridge_stale");
    check(fixture.statuses[0].timed_bomb==1 && fixture.statuses[0].timed_bomb_owner==-1 &&
        fixture.ground->snapshot()==ground && fixture.ledger->snapshot(0)==funds,"stale_explosion_committed_damage");
    fixture.statuses[0].stay=0;
    fixture.world.resolve_terms=[](const auto&,const auto&) {return RichonlineCombatWorld::ResolvedTerms{{},{},0,0};};
    fixture.ledger->adjust(0,funds,{-9900,-900,0,0});auto terminal=fixture.bridge();
    const auto died=terminal.timed_bomb_step(fixture.refs,step,RichonlineMoveCountdown12{9,232},9,policy);
    check(died.bankrupt_actors==std::vector<std::uint8_t>{0} && died.packets.empty() && !fixture.active[0] &&
        !fixture.statuses[0].timed_bomb && !fixture.statuses[0].timed_bomb_owner &&
        fixture.ledger->snapshot(0).funds.cash==0 && *fixture.ledger->snapshot(0).funds.deposit==0,
        "terminal_not_forwarded_before_landing");
}
void transfer_updates_two_shared_statuses(const std::filesystem::path& root) {
    Fixture fixture(root);fixture.refs[1].position=232;
    fixture.statuses[0].timed_bomb=3;fixture.statuses[0].timed_bomb_owner=0;
    fixture.statuses[1].timed_bomb=8;fixture.statuses[1].timed_bomb_owner=-1;
    auto eligibility=raw();eligibility[1]->actor1494=2;eligibility[1]->actor1495=3;
    auto bridge=fixture.bridge();const auto hand=fixture.cards->inventory();
    const auto result=bridge.timed_bomb_step(fixture.refs,{0,2,232,true,false,eligibility},{},9,policy);
    check(result.packets.empty() && fixture.statuses[0].timed_bomb==8 && fixture.statuses[0].timed_bomb_owner==-1 &&
        fixture.statuses[1].timed_bomb==2 && fixture.statuses[1].timed_bomb_owner==0 && fixture.cards->inventory()==hand,
        "shared_transfer_pair_or_extra_gate_wrong");
}
void complete_segment_is_speculative_until_valid_ack(const std::filesystem::path& root) {
    Fixture fixture(root);fixture.refs[0].position=230;fixture.refs[1].position=239;
    fixture.statuses[0].timed_bomb=3;fixture.statuses[0].timed_bomb_owner=0;
    auto bridge=fixture.bridge();const auto funds=fixture.ledger->snapshot(0);
    const auto ground=fixture.ground->snapshot();const auto hand=fixture.cards->inventory();
    const std::array steps{RichonlineTimedBombStepContext{0,2,231,true,false,raw()},
        RichonlineTimedBombStepContext{0,2,232,true,false,raw()},RichonlineTimedBombStepContext{0,2,233,true,false,raw()},
        RichonlineTimedBombStepContext{0,2,234,true,false,raw()}};
    { const auto cancelled=bridge.prepare_timed_bomb_segment(fixture.refs,0,steps,9,policy);
      check(cancelled.plan().accepted_steps==3 && cancelled.plan().actual_stop==233 && !cancelled.committed(),
        "segment_preview_did_not_stop_at_first_explosion"); }
    check(fixture.statuses[0].timed_bomb==3 && fixture.ledger->snapshot(0)==funds && fixture.ground->snapshot()==ground &&
        fixture.cards->inventory()==hand && fixture.refs[0].position==230,"cancelled_preview_changed_authority");
    auto prepared=bridge.prepare_timed_bomb_segment(fixture.refs,0,steps,9,policy);auto copied=prepared;
    rejects([&]{bridge.commit_timed_bomb_segment(fixture.refs,prepared,RichonlineMoveCountdown12{8,233});},
        "richonline_timed_bomb_ack_calendar_mismatch");
    rejects([&]{bridge.commit_timed_bomb_segment(fixture.refs,prepared,RichonlineMoveCountdown12{9,234});},
        "richonline_timed_bomb_ack_position_mismatch");
    rejects([&]{bridge.commit_timed_bomb_segment(fixture.refs,prepared,{});},"richonline_timed_bomb_explosion_ack_missing");
    check(!prepared.committed() && fixture.statuses[0].timed_bomb==3 && fixture.ledger->snapshot(0)==funds &&
        fixture.ground->snapshot()==ground,"bad0012_partially_committed_prior_steps");
    auto other=fixture.bridge();
    rejects([&]{other.commit_timed_bomb_segment(fixture.refs,prepared,RichonlineMoveCountdown12{9,233});},
        "richonline_timed_bomb_segment_token_invalid");
    const auto result=bridge.commit_timed_bomb_segment(fixture.refs,prepared,RichonlineMoveCountdown12{9,233});
    check(prepared.committed() && copied.committed() && !fixture.statuses[0].timed_bomb &&
        !fixture.statuses[0].timed_bomb_owner && fixture.ledger->snapshot(0).funds.cash==6000 &&
        fixture.refs[0].position==230 && result.packets==std::vector<Bytes>{{0x13,0x40,7,0,233,0}},
        "whole_segment_did_not_commit_once_or_stole_route_position");
    const auto after=fixture.ledger->snapshot(0);
    rejects([&]{bridge.commit_timed_bomb_segment(fixture.refs,copied,RichonlineMoveCountdown12{9,233});},
        "richonline_timed_bomb_segment_already_committed");
    check(fixture.ledger->snapshot(0)==after,"copied_token_debited_twice");
}
void normal_segment_transfer_and_empty_segment_commit(const std::filesystem::path& root) {
    Fixture fixture(root);fixture.refs[0].position=230;fixture.refs[1].position=231;
    fixture.statuses[0].timed_bomb=3;fixture.statuses[0].timed_bomb_owner=0;
    auto bridge=fixture.bridge();const auto funds=fixture.ledger->snapshot(0);
    const std::array steps{RichonlineTimedBombStepContext{0,2,231,true,false,raw()},
        RichonlineTimedBombStepContext{0,2,232,true,false,raw()},RichonlineTimedBombStepContext{0,2,233,true,false,raw()}};
    auto plan=bridge.prepare_timed_bomb_segment(fixture.refs,0,steps,9,policy);
    rejects([&]{bridge.commit_timed_bomb_segment(fixture.refs,plan,RichonlineMoveCountdown12{9,233});},
        "richonline_timed_bomb_ack_without_explosion");
    check(fixture.statuses[0].timed_bomb==3 && !fixture.statuses[1].timed_bomb,
        "wrong12_committed_normal_transfer_segment");
    check(bridge.commit_timed_bomb_segment(fixture.refs,plan,{}).packets.empty() && !fixture.statuses[0].timed_bomb &&
        fixture.statuses[1].timed_bomb==2 && fixture.statuses[1].timed_bomb_owner==0 &&
        fixture.ledger->snapshot(0)==funds,"normal_segment_transfer_not_committed_atomically");
    auto empty=bridge.prepare_timed_bomb_segment(fixture.refs,1,{},9,policy);
    check(empty.plan().accepted_steps==0 && empty.plan().actual_stop==231 && !empty.plan().exploding_owner,
        "zero_step_origin_wrong");
    const auto ground=fixture.ground->snapshot();
    check(bridge.commit_timed_bomb_segment(fixture.refs,empty,{}).packets.empty() && fixture.statuses[1].timed_bomb==2 &&
        fixture.ledger->snapshot(0)==funds && fixture.ground->snapshot()==ground && empty.committed(),
        "empty_segment_mutated_timer_ground_or_money");
    rejects([&]{bridge.commit_timed_bomb_segment(fixture.refs,empty,{});},"richonline_timed_bomb_segment_already_committed");
}
void prepared_segment_revalidates_all_shared_authorities(const std::filesystem::path& root) {
    for(unsigned altered=0;altered<6;++altered) {
        Fixture fixture(root);fixture.refs[0].position=230;fixture.refs[1].position=239;
        fixture.statuses[0].timed_bomb=3;fixture.statuses[0].timed_bomb_owner=1;
        auto bridge=fixture.bridge();const std::array steps{RichonlineTimedBombStepContext{0,2,231,true,false,raw()},
            RichonlineTimedBombStepContext{0,2,232,true,false,raw()},RichonlineTimedBombStepContext{0,2,233,true,false,raw()}};
        auto prepared=bridge.prepare_timed_bomb_segment(fixture.refs,0,steps,9,policy);
        switch(altered) {
        case 0:fixture.refs[0].capabilities.in_prison=true;break;
        case 1:fixture.statuses[1].stay=1;break;
        case 2:fixture.ground->place(232,{11,255,255});break;
        case 3: {auto hand=fixture.cards->inventory();hand[2]={1045,1};fixture.cards->commit_inventory(hand);break;}
        case 4:fixture.refs[0].position=231;break;
        default:fixture.ledger->adjust(1,fixture.ledger->snapshot(1),{1,0,0,0});break;
        }
        const auto funds=fixture.ledger->snapshot(0);const auto boss=fixture.ledger->snapshot(1);
        const auto ground=fixture.ground->snapshot();const auto hand=fixture.cards->inventory();
        rejects([&]{bridge.commit_timed_bomb_segment(fixture.refs,prepared,RichonlineMoveCountdown12{9,233});},
            altered==5?"richonline_game_ledger_conflict":altered==2?"richonline_ground_stale":"richonline_combat_bridge_stale");
        check(!prepared.committed() && fixture.statuses[0].timed_bomb==3 && fixture.statuses[0].timed_bomb_owner==1 &&
            fixture.ledger->snapshot(0)==funds && fixture.ledger->snapshot(1)==boss &&
            fixture.ground->snapshot()==ground && fixture.cards->inventory()==hand,"stale_segment_partially_committed");
    }
}
void banana_and_bomb_share_one_ground_commit(const std::filesystem::path& root) {
    Fixture fixture(root);fixture.refs[0].position=230;fixture.refs[1].position=239;
    fixture.statuses[0].timed_bomb=2;fixture.statuses[0].timed_bomb_owner=1;
    fixture.ground->place(231,{30,255,255});fixture.ground->place(232,{30,255,255});
    fixture.ground->place(233,{30,255,255});const auto before=fixture.ground->snapshot();
    auto bridge=fixture.bridge();const std::array steps{RichonlineTimedBombStepContext{0,2,231,true,false,raw()},
        RichonlineTimedBombStepContext{0,2,232,true,false,raw()},RichonlineTimedBombStepContext{0,2,233,true,false,raw()}};
    auto prepared=bridge.prepare_timed_bomb_segment(fixture.refs,0,steps,9,policy);
    check(prepared.plan().accepted_steps==2 && fixture.ground->snapshot()==before,
        "banana_bomb_preview_mutated_ground_or_exceeded_explosion");
    bridge.commit_timed_bomb_segment(fixture.refs,prepared,RichonlineMoveCountdown12{9,232});
    const auto after=fixture.ground->snapshot();
    check(after.revision==before.revision+1 && after.objects.size()==1 && after.objects.contains(233) &&
        !fixture.statuses[0].timed_bomb,"banana_bomb_ground_not_atomic_or_consumed_future_step");
    rejects([&]{bridge.commit_timed_bomb_segment(fixture.refs,prepared,RichonlineMoveCountdown12{9,232});},
        "richonline_timed_bomb_segment_already_committed");
    check(fixture.ground->snapshot()==after,"duplicate_bomb_ack_consumed_future_banana");
}
void bomb_free_segment_consumes_banana_and_rejects_stale_ground(const std::filesystem::path& root) {
    Fixture fixture(root);fixture.refs[0].position=230;fixture.refs[1].position=239;
    fixture.ground->place(231,{11,0,255});const auto funds=fixture.ledger->snapshot(0);
    auto bridge=fixture.bridge();const std::array steps{RichonlineTimedBombStepContext{0,2,231,true,false,raw()},
        RichonlineTimedBombStepContext{0,2,232,true,false,raw()}};
    auto stale=bridge.prepare_timed_bomb_segment(fixture.refs,0,steps,9,policy);
    fixture.ground->place(233,{30,255,255});const auto changed=fixture.ground->snapshot();
    rejects([&]{bridge.commit_timed_bomb_segment(fixture.refs,stale,{});},"richonline_ground_stale");
    check(fixture.ground->snapshot()==changed && fixture.ledger->snapshot(0)==funds,
        "stale_banana_segment_changed_ground_or_funds");
    auto accepted=bridge.prepare_timed_bomb_segment(fixture.refs,0,steps,9,policy);
    bridge.commit_timed_bomb_segment(fixture.refs,accepted,{});
    const auto after=fixture.ground->snapshot();
    check(after.objects.size()==1 && after.objects.contains(233) && fixture.ledger->snapshot(0)==funds,
        "bomb_free_segment_failed_banana_consumption");
}
}
int main(int argc,char** argv) {
    try { if(argc!=2) return 2;const auto root=std::filesystem::path(argv[1]);
        attachment_commits_same_hand_and_status(root);explosion_confirmation_is_atomic_and_one_use(root);
        stale_plan_and_terminal_share_same_authority(root);transfer_updates_two_shared_statuses(root);
        complete_segment_is_speculative_until_valid_ack(root);normal_segment_transfer_and_empty_segment_commit(root);
        prepared_segment_revalidates_all_shared_authorities(root);
        banana_and_bomb_share_one_ground_commit(root);bomb_free_segment_consumes_banana_and_rejects_stale_ground(root);
        std::cout<<"PASS NEW110/0012 shared Bridge atomic inventory/status/funds/ground and terminal\n";
    } catch(const std::exception& error) {std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
