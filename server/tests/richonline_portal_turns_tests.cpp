#include "richonline_boss_turns.hpp"
#include "richonline_portal_landing.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if(!value) throw std::runtime_error(reason); }
Bytes request(std::uint16_t opcode,std::uint16_t counter,std::uint16_t value,std::size_t length=2) {
    Bytes bytes;append_le(bytes,opcode,2);append_le(bytes,counter,2);append_le(bytes,value,length);return bytes;
}
std::uint16_t opcode(const Bytes& packet) { return static_cast<std::uint16_t>(read_le(View(packet).first(2))); }
std::uint8_t incoming_direction(const RichonlineRoadTopology& map,std::int16_t entry) {
    for(std::uint8_t direction=0;direction<4;++direction)
        if(map.cell(entry).neighbors[direction]) return direction;
    throw std::runtime_error("portal_entry_has_no_road");
}
RichonlineBossStartup startup(const RichonlineRoadTopology& map,std::int16_t entry) {
    RichonlineBossStartup value{{3,25,{},{{1,25,0,true}}},
        {0x1234,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
            {{25,115,1,{7,7,7,7,7,7,7,7,7,7},0xb1},{-1,236,1,{},0xc1}}},
        {0x1234,0x4567,1,{{20000,0,150},{100000,0,0}}},{7,-2}};
    value.room.description.record[36]=3;
    const auto direction=incoming_direction(map,entry);
    value.init.participants[1].position=*map.cell(entry).neighbors[direction];
    value.init.participants[1].direction=static_cast<std::uint8_t>((direction+2U)%4U);
    for(const auto& cell:map.cells()) {
        if(cell.walkable && cell.position!=entry && cell.position!=value.init.participants[1].position &&
            cell.static_type!=28 && cell.static_type!=61) {
            value.init.participants[0].position=cell.position;
            break;
        }
    }
    return value;
}
RichonlineBossTurnRules rules(const RichonlineRoadTopology& map,
    std::array<std::int16_t,2> pair,bool& scripted,unsigned& planned,unsigned& landed,
    std::uint8_t die=1) {
    RichonlineBossTurnRules value{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
        [die](std::size_t) { return static_cast<std::size_t>(die-1U); },
        [&landed](const RichonlineLandingContext&) {
            ++landed;return RichonlineLandingResult{{},RichonlineLandingProgress::complete};
        },
        [](View)->RichonlineLandingResult { throw CodecError("unexpected_portal_event_request"); }};
    value.portal_landing=[&map,pair,&scripted,&planned](const RichonlineLandingContext& context) {
        ++planned;
        return plan_richonline_portal_landing(0x1234,map,std::optional{pair},context,scripted);
    };
    return value;
}
void final_portal(const std::filesystem::path& root,const char* map_name,
    std::array<std::int16_t,2> pair) {
    const auto map=load_richonline_road_topology(root/"Map"/map_name);
    for(std::size_t index=0;index<2;++index) {
        const auto entry=pair[index],exit=pair[1U-index];
        auto initial=startup(map,entry);bool scripted=false;unsigned planned=0,landed=0;
        auto selected=rules(map,pair,scripted,planned,landed);
        auto plan=make_richonline_boss_turns(initial,map,selected);
        const auto opening=plan.map_ready();
        check(opening.size()==3 && opcode(opening.back())==0x4011 &&
            read_le(View(opening.back()).subspan(4,2))==static_cast<std::uint16_t>(initial.init.participants[1].position),
            "boss_portal_route_start_wrong");
        const auto response=plan.action({},request(0x11,0x4568,static_cast<std::uint16_t>(entry)));
        check(response.size()==3 && response.front()==request(0x4013,0x1234,
            static_cast<std::uint16_t>(entry)) && opcode(response[1])==0x4010 &&
            planned==1 && landed==0,"final_portal_not_entry_only_or_waited_for_ack");
        const auto human=plan.action({},request(0x10,0x4569,0,4));
        check(human.size()==1 && opcode(human.front())==0x4011,"portal_blocked_human_roll");
        const auto direction=static_cast<std::uint8_t>(human.front()[11]&3U);
        const auto endpoint=map.cell(initial.init.participants[0].position).neighbors[direction];
        check(endpoint.has_value(),"human_followup_route_invalid");
        const auto next=plan.action({},request(0x11,0x4569,static_cast<std::uint16_t>(*endpoint)));
        check(next.size()==3 && opcode(next.back())==0x4011 &&
            read_le(View(next.back()).subspan(4,2))==static_cast<std::uint16_t>(exit),
            "portal_exit_not_authoritative_next_turn_start");
    }
}
void scripted_bypass(const std::filesystem::path& root) {
    const auto map=load_richonline_road_topology(root/"Map"/"V_BS_1_1.emp");
    constexpr std::array<std::int16_t,2> pair{105,229};
    auto initial=startup(map,pair[0]);bool scripted=true;unsigned planned=0,landed=0;
    auto selected=rules(map,pair,scripted,planned,landed);
    auto plan=make_richonline_boss_turns(initial,map,selected);plan.map_ready();
    const auto response=plan.action({},request(0x11,0x4568,static_cast<std::uint16_t>(pair[0])));
    check(response.size()==2 && opcode(response.front())==0x4010 && planned==1 && landed==1,
        "scripted_portal_did_not_enter_shared_phase2");
    const auto human=plan.action({},request(0x10,0x4569,0,4));
    const auto direction=static_cast<std::uint8_t>(human.front()[11]&3U);
    const auto endpoint=map.cell(initial.init.participants[0].position).neighbors[direction];
    check(endpoint.has_value(),"scripted_human_followup_invalid");
    const auto next=plan.action({},request(0x11,0x4569,static_cast<std::uint16_t>(*endpoint)));
    check(read_le(View(next.back()).subspan(4,2))==static_cast<std::uint16_t>(pair[0]),
        "scripted_portal_moved_actor_despite_bypass");
}
void mid_route_61(const std::filesystem::path& root) {
    const auto map=load_richonline_road_topology(root/"Map"/"V_BS_1_1.emp");
    constexpr std::array<std::int16_t,2> pair{105,229};
    auto initial=startup(map,pair[0]);bool scripted=false;unsigned planned=0,landed=0;
    auto selected=rules(map,pair,scripted,planned,landed,2);
    const auto expected=build_richonline_route(map,{initial.init.participants[1].position,
        initial.init.participants[1].direction,2,{}},selected.random);
    check(expected.landings.size()==2 && expected.landings[0]==pair[0] && expected.landings[1]!=pair[0],
        "midroute61_fixture_did_not_cross_entry");
    auto plan=make_richonline_boss_turns(initial,map,selected);plan.map_ready();
    const auto response=plan.action({},request(0x11,0x4568,
        static_cast<std::uint16_t>(expected.landings.back())));
    check(response.size()==2 && opcode(response.front())==0x4010 && planned==0 && landed==1,
        "midroute61_emitted_extra_entry_or_waited_for_ack");
}
void missing_authority(const std::filesystem::path& root) {
    const auto map=load_richonline_road_topology(root/"Map"/"BS_3_1.emp");
    auto initial=startup(map,125);bool scripted=false;unsigned planned=0,landed=0;
    auto selected=rules(map,{125,146},scripted,planned,landed);
    selected.portal_landing={};
    auto plan=make_richonline_boss_turns(initial,map,selected);plan.map_ready();
    try {static_cast<void>(plan.action({},request(0x11,0x4568,125)));}
    catch(const CodecError& error) {
        check(std::string_view(error.what())=="richonline_boss_portal_authority_missing" && landed==0,
            "missing_authority_did_not_fail_closed");return;
    }
    throw std::runtime_error("missing_portal_authority_was_accepted");
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_root_required");const std::filesystem::path root(argv[1]);
        final_portal(root,"BS_3_1.emp",{125,146});
        final_portal(root,"V_BS_1_1.emp",{105,229});
        scripted_bypass(root);mid_route_61(root);missing_authority(root);
        std::cout<<"PASS final28/61, scripted phase2, midroute61 and missing authority\n";
    } catch(const std::exception& error) {std::cerr<<error.what()<<'\n';return 1;}
}
