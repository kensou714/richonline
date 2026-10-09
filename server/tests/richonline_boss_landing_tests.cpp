#include "richonline_boss_landing.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
template<class F> void rejects(F action) {
    try { action(); } catch (const CodecError& error) {
        check(std::string(error.what()) == "richonline_boss_landing_unsupported",error.what()); return;
    }
    throw std::runtime_error("expected_landing_rejection");
}
RichonlineBossStartup startup() {
    RichonlineBossStartup value{{3,25,{},{{1,25,0,true}}},
        {0x1234,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
            {{25,115,1,{7,7,7,7,7,7,7,7,7,7},0xb1},{-1,236,1,{},0xc1}}},
        {0x1234,0x4567,1,{{20000,0,150},{100000,0,0}}},{7,-2}};
    value.room.description.record[36]=3;
    return value;
}
RichonlineBossTurnRules rules(std::size_t steps) {
    return {0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
        [steps](std::size_t) { return steps-1; },
        [](const RichonlineLandingContext& event) { return resolve_richonline_empty_boss_landing(0x1234,event); },
        [](View) -> RichonlineLandingResult { throw CodecError("unexpected_event"); }};
}
Bytes stop(std::uint16_t endpoint) {
    Bytes value; append_le(value,0x11,2); append_le(value,0x4568,2); append_le(value,endpoint,2); return value;
}
void opening_routes_use_real_tiles(const RichonlineRoadTopology& map) {
    check(map.cell(230).static_type==7,"special_coordinate_overrides_raw_minus_one");
    for (std::size_t steps=1; steps<=6; ++steps) {
        auto plan=make_richonline_boss_turns(startup(),map,rules(steps));
        const auto opening=plan.map_ready();
        check(opening.size()==3 && opening[2][8]==steps,"real_opening_route");
        const auto endpoint=static_cast<std::uint16_t>(236-steps);
        if (steps==4 || steps==5) {
            rejects([&] { plan.action({},stop(endpoint)); });
        } else {
            const auto result=plan.action({},stop(endpoint));
            const std::size_t turn_index=steps==3 ? 2U : 1U;
            check(result.size()==turn_index+2,"landing_then_next_human_turn");
            check(result[0]==Bytes({0x13,0x40,0x34,0x12,static_cast<std::uint8_t>(endpoint),0}),"exact_4013_prefix");
            if (steps==3) check(result[1]==Bytes({0x31,0x40,0x34,0x12,0xff}),"boss_shop_exit_before_next_turn");
            check(result[turn_index][0]==0x10 && result[turn_index][4]==0 && result[turn_index+1][0]==0x0f,"next_turn_after_landing");
        }
    }
}
void explicit_guards_reject_unsupported_contexts() {
    const RichonlineLandingContext good{1,0x123,8,-1,3,true,2,false};
    const auto result=resolve_richonline_empty_boss_landing(0xabcd,good);
    check(result.progress==RichonlineLandingProgress::complete &&
        result.messages==std::vector<Bytes>({{0x13,0x40,0xcd,0xab,0x23,0x01}}),"independent_nondefault_wire_oracle");
    auto bad=good; bad.synthetic_actor=false; rejects([&] { resolve_richonline_empty_boss_landing(1,bad); });
    bad=good; bad.game_mode=2; rejects([&] { resolve_richonline_empty_boss_landing(1,bad); });
    bad=good; bad.property_ref=216; rejects([&] { resolve_richonline_empty_boss_landing(1,bad); });
    bad=good; bad.occupied_by_other_actor=true; rejects([&] { resolve_richonline_empty_boss_landing(1,bad); });
    for (const std::uint8_t degree : {std::uint8_t{0},std::uint8_t{5}}) {
        bad=good; bad.road_degree=degree; rejects([&] { resolve_richonline_empty_boss_landing(1,bad); });
    }
    for (const std::int8_t type : {std::int8_t{0},std::int8_t{33},std::int8_t{68}}) {
        bad=good; bad.static_type=type; rejects([&] { resolve_richonline_empty_boss_landing(1,bad); });
    }
    bad=good; bad.position=-1; rejects([&] { resolve_richonline_empty_boss_landing(1,bad); });
    bad=good; bad.actor_slot=8; rejects([&] { resolve_richonline_empty_boss_landing(1,bad); });
    auto plain=good; plain.static_type=-1; plain.road_degree=1;
    check(resolve_richonline_empty_boss_landing(1,plain).progress==RichonlineLandingProgress::complete,"plain_endpoint_supported");
    auto human_shop=good; human_shop.static_type=10; human_shop.synthetic_actor=false;
    rejects([&] { resolve_richonline_empty_boss_landing(1,human_shop); });
}
void engine_supplies_actual_collision_and_mode(const RichonlineRoadTopology& map) {
    auto occupied=startup(); occupied.init.participants[0].position=235;
    auto observed=rules(1);
    observed.landed=[](const RichonlineLandingContext& context) {
        check(context.occupied_by_other_actor && context.collision_resolved,"verified_pair_lost_collision_identity");
        return resolve_richonline_empty_boss_landing(0x1234,context);
    };
    auto collision=make_richonline_boss_turns(occupied,map,std::move(observed)); collision.map_ready();
    const auto continued=collision.action({},stop(235));
    check(continued.size()==3 && continued[0]==Bytes({0x13,0x40,0x34,0x12,235,0}) &&
        continued[1][0]==0x10 && continued[1][4]==0 && continued[2][0]==0x0f,
        "verified_boss_pair_did_not_continue_same_cell");
    auto other_mode=startup(); other_mode.room.description.record[36]=2;
    auto mismatch=make_richonline_boss_turns(other_mode,map,rules(1)); mismatch.map_ready();
    rejects([&] { mismatch.action({},stop(235)); });
}
void human_plain_and_point_landings_preserve_authoritative_points(const RichonlineRoadTopology& map) {
    RichonlineBossLandingState state(0x1234,{150,0});
    RichonlineLandingContext point{0,230,7,-1,3,false,2,false};
    const auto result=state.land(point);
    check(result.progress==RichonlineLandingProgress::complete &&
        result.messages==std::vector<Bytes>{{0x13,0x40,0x34,0x12,230,0}},"point_requires_only_4013");
    check(state.points()==std::array<std::uint32_t,2>{180,0},"human_point_reward_not_mirrored");
    auto plain=point; plain.static_type=-1;
    state.land(plain);
    check(state.points()[0]==180,"plain_tile_awarded_points");
    auto boss=point; boss.actor_slot=1; boss.synthetic_actor=true;
    state.land(boss);
    check(state.points()[1]==0,"synthetic_boss_awarded_points");
    auto card=point; card.static_type=8;
    rejects([&] { state.land(card); });
    auto shop=point; shop.static_type=10;
    rejects([&] { state.land(shop); });
    auto collision=point; collision.occupied_by_other_actor=true;
    rejects([&] { state.land(collision); });
    check(state.points()[0]==180,"rejected_landing_mutated_points");
    RichonlineBossLandingState full(0x1234,{0x7fffffe2U,0});
    try { full.land(point); throw std::runtime_error("point_overflow_accepted"); }
    catch (const CodecError& error) { check(std::string(error.what())=="richonline_boss_points_out_of_range",error.what()); }
    check(full.points()[0]==0x7fffffe2U,"point_overflow_mutated_balance");
    auto initial=startup(); initial.init.participants[0].position=231;
    auto balance=std::make_shared<RichonlineBossLandingState>(0x1234,std::array<std::uint32_t,2>{150,0});
    auto turn_rules=rules(1);
    turn_rules.landed=[balance](const RichonlineLandingContext& context) { return balance->land(context); };
    auto plan=make_richonline_boss_turns(initial,map,std::move(turn_rules));
    plan.map_ready(); plan.action({},stop(235));
    plan.action({},Bytes{0x10,0,0x69,0x45,0,0,0,0});
    const auto completion=plan.action({},stop(230));
    check(completion.size()==4 && completion[0]==Bytes({0x13,0x40,0x34,0x12,230,0}) &&
        completion[1][0]==0x10 && completion[1][4]==1 && balance->points()[0]==180,
        "point_landing_did_not_resume_boss_turn");
    try { plan.action({},stop(230)); throw std::runtime_error("duplicate_point_stop_accepted"); }
    catch (const CodecError&) {}
    check(balance->points()[0]==180,"replayed_point_stop_awarded_twice");
    balance->commit_points(0,180,150);
    try { balance->commit_points(0,180,120); throw std::runtime_error("stale_shop_wallet_accepted"); }
    catch (const CodecError& error) { check(std::string(error.what())=="richonline_boss_points_changed",error.what()); }
    check(balance->points()[0]==150,"stale_shop_wallet_changed_points");
}
void point_tile_variants_follow_new_client_amounts() {
    for (const auto [type,reward]:std::array<std::pair<std::int8_t,std::uint32_t>,3>{{{5,80},{6,50},{7,30}}}) {
        RichonlineBossLandingState state(0x1234,{150,0});
        const RichonlineLandingContext human{0,25,type,-1,3,false,2,false};
        const auto outcome=state.land(human);
        check(outcome.progress==RichonlineLandingProgress::complete &&
            outcome.messages==std::vector<Bytes>{{0x13,0x40,0x34,0x12,25,0}} && state.points()[0]==150+reward,
            "point_tile_variant_reward_or_response_wrong");
        auto boss=human; boss.actor_slot=1; boss.synthetic_actor=true;
        state.land(boss);
        check(state.points()[1]==0,"point_tile_variant_awarded_synthetic_boss");
        RichonlineBossLandingState full(0x1234,{0x7fffffffU-reward+1U,0});
        try { full.land(human); throw std::runtime_error("point_variant_overflow_accepted"); }
        catch (const CodecError& error) { check(std::string(error.what())=="richonline_boss_points_out_of_range",error.what()); }
        check(full.points()[0]==0x7fffffffU-reward+1U,"point_variant_overflow_changed_balance");
    }
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_path_required");
        const auto map=load_richonline_road_topology(std::filesystem::path(argv[1])/"Map/BS_1_1.emp");
        opening_routes_use_real_tiles(map); explicit_guards_reject_unsupported_contexts();
        engine_supplies_actual_collision_and_mode(map);
        human_plain_and_point_landings_preserve_authoritative_points(map);
        point_tile_variants_follow_new_client_amounts();
        std::cout<<"richonline_boss_landing_tests: PASS\n"; return 0;
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
