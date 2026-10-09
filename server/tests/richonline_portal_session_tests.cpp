#include "richonline_boss_session.hpp"
#include "richonline_portal_landing.hpp"
#include <algorithm>
#include <iostream>

namespace {
using namespace richnet;
constexpr std::uint16_t game=0x1234, calendar=0x4567;
void check(bool value,const char* message) { if(!value) throw std::runtime_error(message); }
std::uint16_t opcode(const Bytes& packet) { return static_cast<std::uint16_t>(read_le(View(packet).first(2))); }
Bytes request(std::uint16_t code,std::uint16_t counter,std::uint32_t value,std::size_t width=2) {
    Bytes result;append_le(result,code,2);append_le(result,counter,2);append_le(result,value,width);return result;
}
std::size_t count(const std::vector<Bytes>& packets,std::uint16_t code) {
    return static_cast<std::size_t>(std::count_if(packets.begin(),packets.end(),
        [code](const auto& packet){return opcode(packet)==code;}));
}
struct Approach {std::int16_t position;std::uint8_t heading;};
Approach approach(const RichonlineRoadTopology& map,std::int16_t entry) {
    const auto& cell=map.cell(entry);
    for(std::uint8_t side=0;side<4;++side) if(cell.neighbors[side]) {
        const auto adjacent=*cell.neighbors[side];
        const auto heading=static_cast<std::uint8_t>((side+2U)%4U);
        const auto route=build_richonline_route(map,{adjacent,heading,1,{}},
            [](std::size_t){return std::size_t{0};});
        if(route.landings==std::vector<std::int16_t>{entry}) return {adjacent,heading};
    }
    throw std::runtime_error("portal_approach_missing");
}
struct Start {Approach start;std::int16_t endpoint;};
Start boss_start(const RichonlineRoadTopology& map,std::int16_t human,
    std::array<std::int16_t,2> portals,std::uint8_t dice) {
    for(const auto& cell:map.cells()) {
        if(!cell.walkable || cell.property_ref!=-1 || cell.position==human ||
            cell.position==portals[0] || cell.position==portals[1]) continue;
        for(std::uint8_t heading=0;heading<4;++heading) if(cell.neighbors[heading]) {
            try {
                const auto route=build_richonline_route(map,{cell.position,heading,dice,{}},
                    [](std::size_t){return std::size_t{0};});
                if(route.landings.empty()) continue;
                const auto endpoint=route.landings.back();
                const auto simple=std::all_of(route.landings.begin(),route.landings.end(),
                    [&](std::int16_t position) {
                        const auto& target=map.cell(position);
                        return position!=human && position!=portals[0] && position!=portals[1] &&
                            target.property_ref==-1 && (target.static_type==-1 || target.static_type==5 ||
                            target.static_type==6 || target.static_type==7 || target.static_type==8 ||
                            target.static_type==41 || target.static_type==42);
                    });
                if(!simple) continue;
                return {{cell.position,heading},endpoint};
            } catch(const CodecError&) {}
        }
    }
    throw std::runtime_error("portal_boss_fixture_route_missing");
}
RichonlineMapPackage fixture_package(const RichonlineMapPackage& source) {
    return {source.id,source.map_name,source.special_category,source.chance_event,source.reward_card,
        source.readiness,true,source.load_stage,source.configure,source.closed_chance,source.closed_npcs,
        source.combat,source.opening_hand,source.resource_rules};
}
RichonlineBossStartup startup(const RichonlineBossStage& stage,std::uint32_t category,Approach human,Start boss) {
    RichonlineBossStartup result{{3,25,{},{{1,25,0,true}}},
        {game,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
            {{25,human.position,human.heading,{5,5,5,5,5,5,5,5,5,5},0xb1},
             {-1,boss.start.position,boss.start.heading,{},0xc1}}},
        {game,calendar,1,{{20000,0,150},{100000,0,0}}},{7,-2}};
    result.room.description.record[36]=3;
    auto& extension=result.room.description.extension;extension.resize(88);
    std::copy(stage.map_name.begin(),stage.map_name.end(),extension.begin());
    std::copy(stage.signature.begin(),stage.signature.end(),extension.begin()+32);
    for(std::size_t i=0;i<4;++i) extension[68+i]=static_cast<std::uint8_t>(category>>(8U*i));
    return result;
}
void run_case(const std::filesystem::path& root,std::string_view map_name,
    std::int8_t portal_type,std::int32_t raw) {
    const auto category=portal_type==61 ? 2U : 0U;
    const auto& registered=find_richonline_map_package(map_name,category);
    check(!registered.runtime_enabled,"portal_map_was_accidentally_enabled");
    const auto package=fixture_package(registered);
    const auto resources=load_richonline_map_rule_resources(root,package,category);
    const auto pair=resources.portals[portal_type==28 ? 0U : 1U];
    check(pair.has_value(),"resource_portal_pair_missing");
    const auto entry=(*pair)[0],exit=(*pair)[1];
    const auto human=approach(resources.topology,entry);
    const auto boss=boss_start(resources.topology,human.position,*pair,
        static_cast<std::uint8_t>(resources.stage.boss.max_dice));
    auto selected=startup(resources.stage,category,human,boss);
    RichonlineBossSessionPolicy policy{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
        [](std::size_t){return std::size_t{0};},std::nullopt};
    auto reads=std::make_shared<std::size_t>(0);
    if(raw!=-2) policy.portal_scripted_state=[raw,reads] {++*reads;return raw;};
    if(raw==-2) {
        try {static_cast<void>(make_richonline_boss_session(root,selected,package,policy,{},{}));}
        catch(const CodecError& error) {
            check(std::string_view(error.what())=="richonline_boss_portal_scripted_state_required",
                "portal_missing_reader_wrong_error");return;
        }
        throw std::runtime_error("portal_missing_reader_accepted");
    }
    auto plan=make_richonline_boss_session(root,selected,package,policy,{},{});
    const auto opening=plan.map_ready();
    check(count(opening,0x4011)==1,"portal_opening_missing_boss_route");
    const auto boss_end=plan.action({},request(0x11,calendar+1,
        static_cast<std::uint16_t>(boss.endpoint)));
    check(count(boss_end,0x4013)==1 && count(boss_end,0x4010)==1,
        "portal_fixture_boss_turn_failed");
    const auto roll=plan.action({},request(0x10,calendar+2,0,4));
    check(count(roll,0x4011)==1,"portal_human_roll_failed");
    const auto landing=plan.action({},request(0x11,calendar+2,static_cast<std::uint16_t>(entry)));
    check(*reads>=1 && count(landing,0x4013)==1 && count(landing,0x4010)==1 &&
        landing.front()==request(0x4013,game,static_cast<std::uint16_t>(entry)),
        "portal_landing_did_not_complete_exactly_once");
    check(count(landing,0x4011)==1 && exit!=entry,
        "portal_did_not_start_following_turn");
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_root_required");const std::filesystem::path root(argv[1]);
        run_case(root,"BS_3_1.emp",28,-2);
        run_case(root,"BS_3_1.emp",28,-1);
        run_case(root,"BS_3_1.emp",28,0);
        run_case(root,"V_BS_1_1.emp",61,1);
        run_case(root,"V_BS_1_1.emp",61,2);
        std::cout<<"PASS paired portal session authority and continuation\n";
    } catch(const std::exception& error) {std::cerr<<error.what()<<'\n';return 1;}
}
