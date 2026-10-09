#include "richonline_boss_session.hpp"
#include "richonline_boss_property.hpp"
#include "richonline_chance_landing.hpp"
#include "richonline_opening_hand.hpp"
#include <algorithm>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if(!value) throw std::runtime_error(reason); }
Bytes request(std::uint16_t opcode,std::uint16_t counter,std::uint32_t value,std::size_t width=2) {
    Bytes result; append_le(result,opcode,2); append_le(result,counter,2); append_le(result,value,width); return result;
}
RichonlineBossStartup startup(const RichonlineBossStage& stage,std::uint32_t cash) {
    RichonlineBossStartup value{{3,25,{},{{1,25,0,true}}},
        {0x1234,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
            {{25,122,1,{5,5,5,5,5,5,5,5,5,5},0xb1},{-1,236,1,{},0xc1}}},
        {0x1234,0x4567,1,{{cash,0,150},{100000,0,0}}},{7,-2}};
    value.room.description.record[36]=3;
    auto& extension=value.room.description.extension;
    extension.resize(88);
    std::copy(stage.map_name.begin(),stage.map_name.end(),extension.begin());
    std::copy(stage.signature.begin(),stage.signature.end(),extension.begin()+32);
    return value;
}
struct Selection {
    RichonlinePreparedChanceLanding expected;
    std::vector<std::size_t> bounds;
    std::size_t index;
};
Selection select_category(const std::filesystem::path& root,const RichonlineChanceResources& resources,
    std::uint32_t cash,std::uint8_t category) {
    const auto table=RichonlineChanceEventTable::load(root);
    const auto rules=RichonlineStatusRules::load(root);
    const auto policy=make_richonline_closed_chance_policy(table,"BS_1_1.emp",{1038,1039,1040,1041},true,{0xa5,0x5a});
    const RichonlineLandingContext context{0,121,70,-1,3,false,2,false,{}};
    const RichonlineGameFundsSnapshot funds{{cash,0,150,{}},0};
    const auto inventory=prepare_richonline_opening_hand(0x1234,
        *legacy_richonline_map_package().opening_hand,resources).inventories[0];
    std::vector<std::size_t> bounds;
    prepare_richonline_chance_landing(table,resources,rules,policy,context,0x1234,funds,inventory,
        [&](std::size_t n) { bounds.push_back(n); return std::size_t{0}; });
    check(!bounds.empty(),"chance_selection_empty");
    for(std::size_t index=0;index<bounds.back();++index) {
        std::size_t call=0;
        auto result=prepare_richonline_chance_landing(table,resources,rules,policy,context,0x1234,funds,inventory,
            [&](std::size_t n) {
                check(call<bounds.size() && n==bounds[call],"chance_preparation_changed_rng_sequence");
                return ++call==bounds.size() ? index : std::size_t{0};
            });
        if(result.prepared && result.prepared->category==category &&
            (category!=4 || result.prepared->updated_inventory[0].card_id==1038))
            return {std::move(*result.prepared),std::move(bounds),index};
    }
    throw std::runtime_error("requested_chance_fixture_not_in_native_policy");
}
void session_case(const std::filesystem::path& root,std::uint8_t category,bool failing_log=false) {
    const auto& package=legacy_richonline_map_package();
    const auto stage=package.load_stage(root,0);
    auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
    RichonlineBossProperty property(root,0x1234,{20000,100000},stage);
    const auto price=property.price(104); check(price && *price>1,"fixture_property_price_missing");
    const auto cash=category==2 ? *price-1 : 20000U;
    auto selection=select_category(root,*resources,cash,category);
    struct RandomState {std::size_t opening=0,event_call=0;};
    auto random=std::make_shared<RandomState>();
    RichonlineBossSessionPolicy policy{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
        [random,selection](std::size_t n) {
            if(random->opening<2) {check(n==6,"opening_die_rng_changed");++random->opening;return std::size_t{0};}
            if(random->event_call<selection.bounds.size()) {
                check(n==selection.bounds[random->event_call],"session_event_rng_differs_from_snapshot");
                return ++random->event_call==selection.bounds.size() ? selection.index : std::size_t{0};
            }
            return std::size_t{0};
        },RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}}};
    std::vector<std::string> completed;
    auto plan=make_richonline_boss_session(root,startup(stage,cash),package,policy,resources,
        [&](const std::string& event,const nlohmann::json&) {
            completed.push_back(event);
            if(failing_log) throw std::runtime_error("log_write_failed");
        });
    plan.map_ready(); plan.action({},request(0x11,0x4568,235));
    plan.action({},request(0x10,0x4569,0,4));
    const auto landed=plan.action({},request(0x11,0x4569,121));
    check(landed.size()==5 && landed[0]==Bytes({0x13,0x40,0x34,0x12,121,0}) &&
        landed[1]==selection.expected.packet && landed[2][0]==0x10 && landed[2][4]==1,
        "session_chance_did_not_complete_before_boss_turn");
    check(std::find(completed.begin(),completed.end(),"richonline_chance_completed")!=completed.end(),"chance_completion_not_logged");
    plan.action({},request(0x11,0x456a,234));
    if(category==4) {
        const auto moved=plan.action({},Bytes{103,0,0x6b,0x45,0,0,1,0xa5,0,0,0,0});
        check(moved.size()==2 && moved[0]==Bytes({0xb7,0x40,0x34,0x12,0,0}) &&
            moved[1][0]==0x11 && moved[1][7]==1 && moved[1][8]==1,"chance_card_not_available_to_shared_card_handler");
    } else if(category==8) {
        const auto moved=plan.action({},request(0x10,0x456b,0,4));
        check(moved.size()==1 && moved[0][0]==0x11 && moved[0][7]==6 && moved[0][8]==6,
            "chance_six_step_status_not_used_next_human_turn");
    } else {
        check(cash<*price && selection.expected.updated_funds.cash>=*price,"money_fixture_does_not_cross_affordability");
        plan.action({},request(0x10,0x456b,0,4));
        const auto pending=plan.action({},request(0x11,0x456b,120));
        check(pending==std::vector<Bytes>{{0x13,0x40,0x34,0x12,120,0}},"chance_money_not_seen_by_property_affordability");
        const auto bought=plan.action({},Bytes{0x20,0,0x6b,0x45,0,0,0,0,1,0xaa,0xbb,0xcc});
        check(!bought.empty() && bought[0]==Bytes({0x20,0x40,0x34,0x12,1}),"chance_gain_not_committed_to_shared_property_ledger");
    }
    plan.disconnected();
}
void topology_boundaries(const std::filesystem::path& root) {
    std::size_t checked=0;
    for(const auto name:{"BS_1_1.emp","V_BS_1_1.emp"}) {
        const auto topology=load_richonline_road_topology(root/"Map"/name);
        for(const auto& cell:topology.cells()) if(cell.walkable && cell.static_type>=68 && cell.static_type<=70) {
            const auto degree=std::count_if(cell.neighbors.begin(),cell.neighbors.end(),[](const auto& item){return item.has_value();});
            check(cell.property_ref==-1 && degree>=1 && degree<=4,"chance_road_requires_additional_property_resolution");
            ++checked;
        }
    }
    check(checked==11,"chance_topology_fixture_changed");
}
}
int main(int argc,char** argv) {
    try {check(argc==2,"NEW_resource_root_required");const std::filesystem::path root(argv[1]);
        topology_boundaries(root); session_case(root,2); session_case(root,4); session_case(root,8);
        session_case(root,4,true);
        std::cout<<"PASS real session chance money/property, shared awarded cards, next-turn status, and NEW map road boundaries\n";
    } catch(const std::exception& error) {std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
