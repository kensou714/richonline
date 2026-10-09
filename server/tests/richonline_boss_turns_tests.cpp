#include "richonline_boss_turns.hpp"
#include "richonline_portal_landing.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
template<class F> void rejects(F action, const char* reason) {
    try { action(); } catch (const CodecError& error) { check(std::string(error.what()) == reason,error.what()); return; }
    throw std::runtime_error("expected_rejection");
}
RichonlineBossStartup startup() {
    return {{3,25,{},{{1,25,0,true}}},
        {0x1234,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
            {{25,115,1,{7,7,7,7,7,7,7,7,7,7},0xb1},{-1,236,1,{},0xc1}}},
        {0x1234,0x4567,1,{{20000,0,150},{100000,0,0}}},{7,-2}};
}
Bytes request(std::uint16_t opcode, std::uint32_t value, std::size_t length=2,
    std::uint16_t counter=0x4568) {
    Bytes result; append_le(result,opcode,2); append_le(result,counter,2); append_le(result,value,length); return result;
}
RichonlineBossTurnRules rules() {
    return {0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
        [](std::size_t) { return std::size_t{0}; },
        [](const RichonlineLandingContext&) { return RichonlineLandingResult{{},RichonlineLandingProgress::complete}; },
        [](View) -> RichonlineLandingResult { throw CodecError("test_event_unexpected"); }};
}
void boss_first_waits_for_endpoint(const RichonlineRoadTopology& map) {
    auto selected = rules(); std::vector<RichonlineLandingContext> landed;
    selected.landed = [&](const RichonlineLandingContext& event) {
        landed.push_back(event); return RichonlineLandingResult{{},RichonlineLandingProgress::complete};
    };
    auto plan = make_richonline_boss_turns(startup(),map,selected);
    const auto opening = plan.map_ready();
    check(opening.size()==3 && opening[0]==Bytes({0x10,0x40,0x34,0x12,1,1,0,0xa2}),"boss_opening_turn");
    check(opening[1]==Bytes({0x0f,0x42,0x34,0x12,0xff,0xff}),"empty_status_phase_required");
    check(opening[2][0]==0x11 && opening[2][4]==236 && opening[2][6]==1 && opening[2][8]==1 &&
          opening[2][9]==0xf9 && opening[2][10]==9 && (opening[2][11]&3)==1,"boss_auto_route");
    rejects([&] { plan.map_ready(); },"richonline_boss_duplicate_opening");
    for (const auto opcode : {0x12U,0x2aU})
        rejects([&] { plan.action({},request(static_cast<std::uint16_t>(opcode),235)); },"richonline_boss_intermediate_effect_unsupported");
    rejects([&] { plan.action({},request(0x28,235)); },"richonline_boss_bank_checkpoint_mismatch");
    rejects([&] { plan.action({},request(0x10,0,4)); },"richonline_boss_roll_out_of_phase");
    rejects([&] { plan.action({},request(0x11,234)); },"richonline_boss_endpoint_mismatch");
    const auto human = plan.action({},request(0x11,235));
    check(landed.size()==1 && landed[0].actor_slot==1 && landed[0].position==235 &&
          landed[0].property_ref==map.cell(235).property_ref,"boss_landing_once");
    check(human.size()==2 && human[0][0]==0x10 && human[0][4]==0 && human[1][0]==0x0f,"human_waits_for_roll");
    rejects([&] { plan.action({},request(0x11,235)); },"richonline_boss_stop_out_of_phase");
    rejects([&] { plan.action({},request(0x10,0,4)); },"richonline_boss_roll_counter_mismatch");
    rejects([&] { plan.action({},request(0x10,1,4,0x4569)); },"richonline_boss_roll_parameter_unsupported");
    const auto move = plan.action({},request(0x10,0,4,0x4569));
    check(move.size()==1 && move[0][0]==0x11 && move[0][4]==115,"human_roll_route");
    const auto next = plan.action({},request(0x11,114,2,0x4569));
    check(next.size()==3 && next[0][4]==1 && next[2][4]==235,"boss_next_turn_uses_updated_position");
    plan.disconnected();
    rejects([&] { plan.action({},request(0x11,234)); },"richonline_boss_session_closed");
}
void landing_waits_for_its_completion(const RichonlineRoadTopology& map) {
    auto selected=rules(); unsigned events=0;
    selected.landed=[](const RichonlineLandingContext&) {
        return RichonlineLandingResult{{Bytes{0x40,0x40,0x34,0x12}},RichonlineLandingProgress::await_event};
    };
    selected.event=[&](View packet) {
        check(read_le(packet.first(2))==0x55,"landing_event_routed"); ++events;
        return RichonlineLandingResult{{},RichonlineLandingProgress::complete};
    };
    auto plan=make_richonline_boss_turns(startup(),map,selected); plan.map_ready();
    const auto pending=plan.action({},request(0x11,235));
    check(pending.size()==1 && pending[0][0]==0x40,"landing_cannot_auto_skip");
    rejects([&] { plan.action({},request(0x10,0,4)); },"richonline_boss_roll_out_of_phase");
    const auto next=plan.action({},request(0x55,0));
    check(events==1 && next.size()==2 && next[0][4]==0,"event_completion_advances_once");
    rejects([&] { plan.action({},request(0x55,0)); },"richonline_boss_action_out_of_phase");
}
void terminal_and_failed_landings(const RichonlineRoadTopology& map) {
    auto selected=rules(); unsigned calls=0;
    selected.landed=[&](const RichonlineLandingContext&) {
        ++calls;
        if (calls==1) throw CodecError("test_landing_rejected");
        return RichonlineLandingResult{{Bytes{0x0b,0x40,0x34,0x12}},RichonlineLandingProgress::finished};
    };
    auto plan=make_richonline_boss_turns(startup(),map,selected); plan.map_ready();
    rejects([&] { plan.action({},request(0x11,235)); },"test_landing_rejected");
    const auto end=plan.action({},request(0x11,235));
    check(end.size()==1 && end[0][0]==0x0b && calls==2,"finish_does_not_start_another_turn");
    rejects([&] { plan.action({},request(0x11,235)); },"richonline_boss_session_closed");
    selected=rules(); selected.random=[](std::size_t n) { return n; };
    auto bad_random=make_richonline_boss_turns(startup(),map,selected);
    rejects([&] { bad_random.map_ready(); },"richonline_boss_random_out_of_range");
    selected=rules(); selected.route_wire.local_reserve_charge=1;
    rejects([&] { make_richonline_boss_turns(startup(),map,selected); },"richonline_boss_paid_roll_unsupported");
}
void final_junction_preserves_actor_and_next_route(const RichonlineRoadTopology& map) {
    std::uint8_t incoming=0;
    while (incoming<4 && !map.cell(178).neighbors[incoming]) ++incoming;
    check(incoming<4,"junction_fixture_no_incoming_edge");
    auto initial=startup(); initial.init.participants[0].position=*map.cell(178).neighbors[incoming];
    initial.init.participants[0].direction=static_cast<std::uint8_t>((incoming+2U)%4U);
    auto selected=rules();
    selected.landed=[](const RichonlineLandingContext& context) {
        return RichonlineLandingResult{{},context.actor_slot==0 ?
            RichonlineLandingProgress::await_event : RichonlineLandingProgress::complete,
            context.actor_slot==0 ? std::optional<std::uint16_t>{0x30} : std::nullopt};
    };
    selected.event=[](View) { return RichonlineLandingResult{{Bytes{0x31,0x40,0x34,0x12,0xff}},RichonlineLandingProgress::complete}; };
    auto plan=make_richonline_boss_turns(initial,map,selected);
    plan.map_ready(); plan.action({},request(0x11,235));
    plan.action({},request(0x10,0,4,0x4569)); plan.action({},request(0x11,178,2,0x4569));
    const auto closed=plan.action({},request(0x30,0xffff,2,0x4569));
    check(closed.size()==1 && closed.front()[0]==0x31,"junction_started_next_actor_before_direction_choice");
    check(plan.action({},request(0x30,0xffff,2,0x4569)).empty(),"late_shop_exit_broke_pending_junction");
    std::uint8_t direction=0;
    while (direction<4 && (!map.cell(178).neighbors[direction] || direction==incoming)) ++direction;
    check(direction<4,"junction_fixture_no_legal_direction");
    auto choice=request(0x34,direction,2,0x4569); choice[5]=0xcc;
    const auto resolved=plan.action({},choice);
    check(resolved.size()==4 && resolved[0]==Bytes({0x35,0x40,0x34,0x12,direction}) &&
        resolved[1][0]==0x10 && resolved[1][4]==1,"junction_response_must_precede_next_actor");
    check(plan.retired_action && plan.retired_action(choice),"late_junction_choice_not_retired");
    check(plan.retired_action(request(0x30,0xffff,2,0x4569)),"junction_lost_previous_shop_retirement");
    plan.action({},request(0x11,234,2,0x456a));
    const auto movement=plan.action({},request(0x10,0,4,0x456b));
    check(movement.size()==1 && (movement[0][11]&3)==direction,"chosen_heading_lost_in_turn_engine");
    const auto endpoint=static_cast<std::uint16_t>(*map.cell(178).neighbors[direction]);
    plan.action({},request(0x11,endpoint,2,0x456b));
}
void portal_landing_acknowledges_entry_but_next_turn_starts_at_exit(const std::filesystem::path& root) {
    const auto map=load_richonline_road_topology(root/"Map"/"V_BS_1_1.emp");
    auto initial=startup();
    initial.init.participants[0].position=99; initial.init.participants[0].direction=1;
    initial.init.participants[1].position=106; initial.init.participants[1].direction=1;
    initial.room.description.record[36]=3;
    auto selected=rules();
    const std::optional pair{std::array<std::int16_t,2>{105,229}};
    selected.portal_landing=[&](const RichonlineLandingContext& context) {
        return plan_richonline_portal_landing(0x1234,map,pair,context,false);
    };
    selected.landed=[](const RichonlineLandingContext& context) {
        check(context.static_type!=61,"portal_delegated_to_ordinary_landing");
        return RichonlineLandingResult{{},RichonlineLandingProgress::complete};
    };
    auto plan=make_richonline_boss_turns(initial,map,selected);
    plan.map_ready();
    const auto teleported=plan.action({},request(0x11,105));
    check(teleported.size()==3 && teleported[0]==Bytes({0x13,0x40,0x34,0x12,105,0}) && teleported[1][4]==0,
        "portal_entry_confirmation_or_continuation_wrong");
    plan.action({},request(0x10,0,4,0x4569));
    const auto route=build_richonline_route(map,{99,1,1,{}},selected.random);
    const auto next=plan.action({},request(0x11,static_cast<std::uint16_t>(route.landings.back()),2,0x4569));
    check(next.size()==3 && read_le(View(next[2]).subspan(4,2))==229 && (next[2][11]&3)==1,
        "portal_exit_not_authoritative_next_turn_spawn");
}
void upgrade_to_research_retires_both_requests(const RichonlineRoadTopology& map) {
    for(const bool timeout:{false,true}) {
        auto selected=rules();std::vector<std::uint8_t> ticks;unsigned upgrades=0,research=0;bool waiting=false;
        selected.research_turn_started=[&](std::uint8_t actor){ticks.push_back(actor);};
        selected.landed=[](const RichonlineLandingContext& context) {
            return RichonlineLandingResult{{},context.actor_slot==0?RichonlineLandingProgress::await_event:
                RichonlineLandingProgress::complete,context.actor_slot==0?std::optional<std::uint16_t>{0x38}:std::nullopt};
        };
        selected.event=[&](View plain) {
            const auto opcode=read_le(plain.first(2));
            if(opcode==0x38) {
                ++upgrades;waiting=true;
                return RichonlineLandingResult{{Bytes{0x3e,0x40,0x34,0x12,1}},RichonlineLandingProgress::await_event,0x39};
            }
            check(opcode==0x39,"research_received_wrong_pending_opcode");++research;waiting=false;
            return RichonlineLandingResult{{Bytes{0x3f,0x40,0x34,0x12,1}},RichonlineLandingProgress::complete};
        };
        selected.poll=[&]()->std::optional<RichonlineLandingResult> {
            if(!waiting)return {};waiting=false;
            return RichonlineLandingResult{{Bytes{0x3f,0x40,0x34,0x12,0xff}},RichonlineLandingProgress::complete};
        };
        auto plan=make_richonline_boss_turns(startup(),map,selected);plan.map_ready();
        plan.action({},request(0x11,235));plan.action({},request(0x10,0,4,0x4569));
        plan.action({},request(0x11,114,2,0x4569));
        const auto upgrade=request(0x38,1,2,0x4569),choice=request(0x39,1,2,0x4569);
        const auto upgraded=plan.action({},upgrade);
        check(upgraded.size()==1 && plan.action({},upgrade).empty() && upgrades==1 && ticks==std::vector<std::uint8_t>{1,0},
            "upgrade_to_research_replayed_upgrade_or_ticked_early");
        const auto done=timeout?plan.poll():plan.action({},choice);
        check(done.size()==4 && done[0][0]==0x3f && ticks==std::vector<std::uint8_t>{1,0,1},
            "research_completion_or_tick_failed");
        check(plan.action({},choice).empty() && plan.action({},upgrade).empty() && upgrades==1 && research==(timeout?0U:1U),
            "late_research_or_upgrade_repeated_effect");
        check(plan.retired_action(choice) && plan.retired_action(upgrade),"research_or_upgrade_not_retired");
    }
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_path_required");
        const auto map=load_richonline_road_topology(std::filesystem::path(argv[1])/"Map/BS_1_1.emp");
        boss_first_waits_for_endpoint(map); landing_waits_for_its_completion(map); terminal_and_failed_landings(map);
        final_junction_preserves_actor_and_next_route(map);
        upgrade_to_research_retires_both_requests(map);
        portal_landing_acknowledges_entry_but_next_turn_starts_at_exit(std::filesystem::path(argv[1]));
        auto missing=rules(); missing.landed={};
        rejects([&] { make_richonline_boss_turns(startup(),map,missing); },"richonline_boss_turn_rules_required");
        std::cout<<"richonline_boss_turns_tests: PASS\n"; return 0;
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
