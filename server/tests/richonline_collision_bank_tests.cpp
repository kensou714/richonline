#include "richonline_boss_turns.hpp"
#include "richonline_game_bank.hpp"
#include "richonline_game_ledger.hpp"
#include "richonline_npc_session.hpp"
#include "original_map.hpp"
#include <algorithm>
#include <iostream>

namespace {
using namespace richnet;
constexpr std::uint16_t game=0x1234,calendar=0x4567;
void check(bool value,const char* message) {if(!value) throw std::runtime_error(message);}
Bytes request(std::uint16_t opcode,std::uint16_t counter,std::uint16_t value,std::size_t length=2) {
    Bytes result;append_le(result,opcode,2);append_le(result,counter,2);append_le(result,value,length);return result;
}
std::uint16_t opcode(const Bytes& bytes) {return static_cast<std::uint16_t>(read_le(View(bytes).first(2)));}
void codes(const std::vector<Bytes>& packets,std::initializer_list<std::uint16_t> expected) {
    std::vector<std::uint16_t> actual;for(const auto& packet:packets)actual.push_back(opcode(packet));
    check(actual==std::vector<std::uint16_t>(expected),"collision_bank_packet_order_changed");
}
RichonlineRoadTopology bank_geometry() {
    OriginalEmp emp{3,10,1,{}, {},Bytes(8+68*10,0xff),8,8+64*10,0,0};
    for(std::size_t position=0;position<10;++position)
        emp.payload[emp.terrain_offset+64*position]=8;
    emp.payload[emp.tile_types_offset+4*3]=9;
    return richonline_road_topology(emp);
}
struct Fixture {
    std::string map_name;
    RichonlineRoadTopology topology;
    std::int16_t bank_position=-1,start_position=-1;
    std::uint8_t heading=0;
    std::shared_ptr<RichonlineGameLedger> ledger;
    std::shared_ptr<RichonlineBossCards> cards;
    std::shared_ptr<RichonlineGroundObjects> ground;
    std::shared_ptr<RichonlineGameBank> bank;
    RichonlineStartupPlan plan;
    std::vector<RichonlineLandingContext> preflight;
    bool reject_preflight=false;
    Fixture(const std::filesystem::path& root,std::string selected_map,bool human_starts_on_bank)
        : map_name(std::move(selected_map)),topology(bank_geometry()) {
        std::vector<std::int16_t> roads;
        for(const auto& cell:topology.cells()) {
            if(cell.walkable)roads.push_back(cell.position);
            if(bank_position<0 && cell.walkable && cell.static_type==9 && cell.property_ref==-1 &&
                std::count_if(cell.neighbors.begin(),cell.neighbors.end(),[](const auto& n){return n.has_value();})==2) {
                for(std::uint8_t direction=0;direction<4;++direction) if(cell.neighbors[direction]) {
                    bank_position=cell.position;start_position=*cell.neighbors[direction];
                    heading=static_cast<std::uint8_t>((direction+2U)%4U);break;
                }
            }
        }
        if(bank_position<0) {
            std::string detail="bank_fixture_missing map="+map_name;
            for(const auto& cell:topology.cells()) if(cell.static_type==9)
                detail+=" pos="+std::to_string(cell.position)+" property="+std::to_string(cell.property_ref);
            throw std::runtime_error(detail);
        }
        ledger=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{
            {1000,200,150,{}},{5000,400,0,{}}});
        const auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
        cards=std::make_shared<RichonlineBossCards>(resources,game,
            RichonlineBossCardPolicy{map_name,17,1038,{0xa5,0x5a}});
        ground=std::make_shared<RichonlineGroundObjects>(std::move(roads));
        bank=std::make_shared<RichonlineGameBank>(game,RichonlineGameBankWirePolicy{0xa5,{0xb6,0xc7}},
            []{return RichonlineGameBank::Clock::time_point{};});
        auto npc_policy=RichonlineNpcSessionPolicy{
            {0,0,0,5,1000,{0,1,3},0x91,0x92,0x93,0x94,false},19,{1038,1044},{25,-1},
            {load_richonline_npc_affix(root,0),load_richonline_npc_affix(root,1)},
            "test-fixed-20",[](std::uint8_t,std::int8_t,const auto&){return std::int16_t{20};}};
        auto npcs=std::make_shared<RichonlineNpcSession>(game,map_name,RichonlineNpcRules::load(root),resources,
            std::make_shared<const RichonlineChanceEventTable>(RichonlineChanceEventTable::load(root)),
            ledger,cards,ground,std::move(npc_policy));
        RichonlineBossStartup startup{{3,25,{},{{1,25,0,true}}},
            {game,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
                {{25,human_starts_on_bank ? bank_position : start_position,heading,{7,7,7,7,7,7,7,7,7,7},0xb1},
                 {-1,start_position,heading,{},0xc1}}},
            {game,calendar,1,{{1000,200,150},{5000,400,0}}},{7,-2}};
        startup.room.description.record[36]=3;
        RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
            [](std::size_t){return std::size_t{0};},
            [](const RichonlineLandingContext&)->RichonlineLandingResult{throw CodecError("unexpected_bank_fallback");},
            [](View)->RichonlineLandingResult{throw CodecError("unexpected_bank_event_fallback");}};
        rules.bank=bank;rules.ledger=ledger;rules.cards=cards;rules.npcs=npcs;
        rules.npc_landing_preflight=[this](const RichonlineLandingContext& context) {
            preflight.push_back(context);
            if(reject_preflight || (context.occupied_by_other_actor && !context.collision_resolved))
                throw CodecError("test_collision_continuation_not_admitted");
            const auto& cell=topology.cell(context.position);
            check(cell.static_type==9 && cell.property_ref==-1 && context.game_mode==3,
                "unexpected_actual_bank_context");
        };
        plan=make_richonline_boss_turns(startup,topology,std::move(rules));
        plan.map_ready();
    }
    Bytes stop(std::uint16_t counter) const {return request(0x11,counter,static_cast<std::uint16_t>(bank_position));}
};
void boss_npc_then_occupied_bank(const std::filesystem::path& root,const std::string& map) {
    Fixture f(root,map,true);f.ground->place(f.bank_position,{0,0x91,0x92});
    const auto result=f.plan.action({},f.stop(calendar+1));
    codes(result,{0x4013,0x4022,0x4018,0x402a,0x4010,0x420f});
    check(f.preflight.size()==1 && f.preflight[0].occupied_by_other_actor &&
        f.preflight[0].collision_resolved && !f.bank->active(),"BOSS_overlap_not_admitted");
    check(f.ledger->snapshot(0).funds.cash==980 && f.ledger->snapshot(1).funds.cash==5020 &&
        !f.ground->snapshot().objects.contains(f.bank_position),"BOSS_money_pickup_not_once");
}
void human_npc_then_occupied_bank(const std::filesystem::path& root,const std::string& map) {
    Fixture f(root,map,false);f.plan.action({},f.stop(calendar+1));
    f.ground->place(f.bank_position,{3,0x91,0x92});
    f.plan.action({},request(0x10,calendar+2,0,4));
    const auto result=f.plan.action({},f.stop(calendar+2));
    codes(result,{0x4013,0x4023,0x4018});
    check(f.preflight.back().occupied_by_other_actor && f.preflight.back().collision_resolved &&
        f.bank->active(),"human_overlap_not_admitted_or_bank_skipped");
    const auto inventory=f.cards->inventory();
    check(std::count_if(inventory.begin(),inventory.end(),[](const auto& slot){return slot.card_id!=-1;})==2,
        "fortune_did_not_grant_two_cards");
    auto exit=request(0x27,calendar+2,2);exit.insert(exit.end(),{0xcc,0xdd});append_le(exit,0,4);
    const auto closed=f.plan.action({},exit);
    codes(closed,{0x402a,0x4010,0x420f,0x4011});
    check(!f.bank->active() && f.cards->inventory()==inventory && f.plan.action({},exit).empty(),
        "bank_replay_repeated_collision_or_fortune");
}
void preflight_before_npc_commit(const std::filesystem::path& root,const std::string& map) {
    Fixture f(root,map,true);f.ground->place(f.bank_position,{0,0x91,0x92});f.reject_preflight=true;
    const auto before_ground=f.ground->snapshot();const auto before_cards=f.cards->inventory();
    const std::array before_funds{f.ledger->snapshot(0),f.ledger->snapshot(1)};
    try {static_cast<void>(f.plan.action({},f.stop(calendar+1)));}
    catch(const CodecError& error) {
        check(std::string_view(error.what())=="test_collision_continuation_not_admitted" &&
            f.ground->snapshot()==before_ground && f.cards->inventory()==before_cards &&
            f.ledger->snapshot(0)==before_funds[0] && f.ledger->snapshot(1)==before_funds[1] &&
            !f.bank->active(),"preflight_failure_mutated_shared_state");
        f.reject_preflight=false;codes(f.plan.action({},f.stop(calendar+1)),
            {0x4013,0x4022,0x4018,0x402a,0x4010,0x420f});return;
    }
    throw std::runtime_error("rejected_collision_preflight_was_ignored");
}
}
int main(int argc,char** argv) {
    try {check(argc==2,"resource_root_required");const std::filesystem::path root(argv[1]);
        const auto bs1=load_richonline_road_topology(root/"Map"/"BS_1_1.emp");
        check(std::none_of(bs1.cells().begin(),bs1.cells().end(),[](const auto& cell){return cell.static_type==9;}),
            "BS1_1_resource_bank_coverage_changed");
        const std::string selected="BS_1_1.emp";
        boss_npc_then_occupied_bank(root,selected);human_npc_then_occupied_bank(root,selected);
        preflight_before_npc_commit(root,selected);
        std::cout<<"PASS synthetic occupied bank with real BS1_1 NPC resources, human/BOSS order, no duplicate4013, replay and preflight atomicity; actual BS1_1 has no bank\n";
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
