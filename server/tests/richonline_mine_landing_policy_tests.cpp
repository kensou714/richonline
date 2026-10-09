#include "richonline_mine_landing_policy.hpp"
#include "richonline_boss_stage.hpp"

#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* why) {if(!value) throw std::runtime_error(why);}
void rejects(auto action,const char* why) {
    try {action();} catch(const CodecError& error) {check(std::string(error.what())==why,error.what());return;}
    throw std::runtime_error("missing_policy_rejection");
}
RichonlineCombatSessionView state() {
    RichonlineCombatSessionView result;result.game_id=7;
    for(std::uint8_t slot=0;slot<2;++slot) {
        RichonlineCombatActorView actor;actor.slot=slot;actor.position=static_cast<std::int16_t>(240+slot);
        actor.status.possession=slot==0?std::optional<std::int8_t>{0}:std::optional<std::int8_t>{7};
        actor.status.sleepwalking=slot==0?1:0;actor.funds={{10000,1000,10,{}},0};result.actors[slot]=actor;
    }
    return result;
}
void actual_map_subset_is_live_and_status_sensitive(const std::filesystem::path& root) {
    const auto topology=load_richonline_road_topology(root/"Map"/"BS_1_1.emp");
    std::vector<RichonlineLandingContext> preflighted;
    RichonlineMineLandingPolicy policy(topology,3,0,[&](const auto& context) {
        preflighted.push_back(context);
        if(context.actor_slot==1 && context.actor_status.possession==7 && context.actor_status.sleepwalking)
            throw CodecError("controlled_static_landing_unsupported");
    });
    auto snapshot=state();
    const auto pool=policy.allowed_positions(snapshot);
    check(!pool.empty(),"actual_bs_1_1_mine_pool_empty");
    for(const auto position:pool) {
        const auto& cell=topology.cell(position);
        check(cell.walkable && cell.property_ref==-1 && !topology.portal_destination(position) &&
            (cell.static_type==-1 || cell.static_type==5 || cell.static_type==6 || cell.static_type==7),
            "candidate_not_closed_ground_reward_subset");
    }
    check(std::ranges::find_if(pool,[&](auto p){return topology.cell(p).static_type==0;})==pool.end(),
        "unsupported_type_zero_admitted");
    check(std::ranges::find_if(pool,[&](auto p){return topology.cell(p).static_type==5;})!=pool.end() ||
        std::ranges::find_if(pool,[&](auto p){return topology.cell(p).static_type==6;})!=pool.end() ||
        std::ranges::find_if(pool,[&](auto p){return topology.cell(p).static_type==7;})!=pool.end(),
        "verified_5_6_7_reward_cells_absent_from_candidate_pool");
    check(!preflighted.empty() && std::ranges::all_of(preflighted,[](const auto& context) {
        return context.actor_slot==0 || context.actor_slot==1;
    }),"preflight_not_per_actor");
    auto no_status=snapshot;no_status.actors[1]->status.sleepwalking=0;
    const auto land=std::ranges::find_if(pool,[&](auto p){return topology.cell(p).static_type==5;});
    const auto points=land!=pool.end()?*land:*pool.begin();
    check(policy.assess(points,snapshot).allowed && policy.assess(points,no_status).allowed,
        "independent_status_states_rejected");
    snapshot.actors[1]->status.sleepwalking=1;
    check(!policy.assess(points,snapshot).allowed && policy.assess(points,no_status).allowed,
        "other_actor_real_landing_preflight_not_used");
    snapshot.actors[1]->status.sleepwalking=0;
    snapshot.dynamic_npcs.push_back({points,3});
    check(policy.assess(points,snapshot).reason=="ground_occupied","existing_ground_object_not_excluded");
    snapshot.dynamic_npcs.clear();snapshot.actors[1]->position=static_cast<std::int16_t>(points);
    check(policy.assess(points,snapshot).reason=="actor_collision_excluded","other_actor_collision_not_excluded");
}
void rejected_continuations_and_contract(const std::filesystem::path& root) {
    const auto topology=load_richonline_road_topology(root/"Map"/"BS_1_1.emp");
    rejects([&] {RichonlineMineLandingPolicy invalid(topology,0,0,[](const auto&){});},
        "richonline_mine_landing_policy_invalid");
    rejects([&] {RichonlineMineLandingPolicy invalid(topology,3,2,[](const auto&){});},
        "richonline_mine_landing_policy_invalid");
    RichonlineMineLandingPolicy policy(topology,3,0,[](const auto&){});
    const auto snapshot=state();
    for(const auto& cell:topology.cells()) {
        const auto result=policy.assess(cell.position,snapshot);
        if(cell.walkable && cell.property_ref!=-1)
            check(!result.allowed && result.reason=="property_continuation_excluded","property_tile_admitted");
        if(topology.portal_destination(cell.position))
            check(!result.allowed && result.reason=="portal_continuation_excluded","portal_tile_admitted");
        if(cell.walkable && cell.property_ref==-1 &&
            cell.static_type!=-1 && cell.static_type!=5 && cell.static_type!=6 && cell.static_type!=7)
            check(!result.allowed && result.reason=="static_continuation_excluded","unimplemented_static_admitted");
    }
    rejects([&] {static_cast<void>(policy.assess(-1,snapshot));},"richonline_mine_landing_position_invalid");
    auto malformed=snapshot;malformed.actors[0]->slot=3;
    const auto any=policy.allowed_positions(snapshot);
    check(!any.empty(),"closed_mine_policy_test_has_no_candidates");
    rejects([&] {static_cast<void>(policy.assess(any.front(),malformed));},"richonline_mine_landing_actor_invalid");
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_root_required");
        actual_map_subset_is_live_and_status_sensitive(argv[1]);
        rejected_continuations_and_contract(argv[1]);
        std::cout<<"PASS NEW BOSS mine landing capability subset and per-actor preflight\n";
    } catch(const std::exception& error) {std::cerr<<error.what()<<'\n';return 1;}
}
