#include "richonline_chance_landing.hpp"
#include <iostream>
namespace {
using namespace richnet;
void check(bool value,std::string_view message) {if(!value) throw std::runtime_error(std::string(message));}
template<class F> void rejects(F call,std::string_view expected={}) {try {call();} catch(const CodecError& error) {
    if(!expected.empty()) check(error.what()==expected,"wrong rejection"); return;
} throw std::runtime_error("expected rejection");}
void real_map(const std::filesystem::path& root) {
    const auto table=RichonlineChanceEventTable::load(root); const auto resources=RichonlineChanceResources::load(root);
    const auto rules=RichonlineStatusRules::load(root);
    auto policy=make_richonline_closed_chance_policy(table,"V_BS_1_1.emp",{1038,1039,1040,1041},true,{0xa5,0x5a});
    RichonlineLandingContext human{0,100,68,-1,3,false,3,false,{}};
    RichonlineGameFundsSnapshot funds{{12000,0,350,25000},7}; RichonlineChanceInventory inventory{};
    auto zero=[](std::size_t) {return std::size_t{0};};
    policy.entries={{13,1}};
    const auto money=prepare_richonline_chance_landing(table,resources,rules,policy,human,99,funds,inventory,zero);
    check(money.prepared && money.prepared->expected_funds==funds && money.prepared->updated_funds.cash==13950,"money actual row");
    check(money.prepared->updated_funds.tickets==350 && money.prepared->updated_funds.reserve==25000,"independent currencies");
    check(funds.funds.cash==12000 && inventory[0].card_id==-1,"pure planning");
    policy.entries={{2,1}};
    const auto card=prepare_richonline_chance_landing(table,resources,rules,policy,human,99,funds,inventory,zero);
    check(card.prepared && card.prepared->updated_inventory[0].card_id==1038 && card.prepared->packet[4]==2,"Zhao event not normal index");
    inventory.fill({1038,1});
    const auto full=prepare_richonline_chance_landing(table,resources,rules,policy,human,99,funds,inventory,zero);
    check(full.prepared && full.prepared->updated_inventory==inventory,"full completes without disconnect");
    policy.entries={{22,1}}; human.static_type=70;
    const auto status=prepare_richonline_chance_landing(table,resources,rules,policy,human,99,funds,inventory,zero);
    check(status.prepared && status.prepared->updated_status.one_step==rules.fixed_step_turns+1,"motion status prepared");
    policy.entries={{17,1}}; funds.funds.cash=1950; human.static_type=69;
    const auto insolvent=prepare_richonline_chance_landing(table,resources,rules,policy,human,99,funds,inventory,zero);
    check(!insolvent.prepared && insolvent.disposition==RichonlineChanceLandingDisposition::no_closed_event &&
        insolvent.excluded_events[0]=="17:bankruptcy_flow_required","no fake bankruptcy continuation");
    policy.entries={{17,1},{13,1}};
    const auto alternative=prepare_richonline_chance_landing(table,resources,rules,policy,human,99,funds,inventory,zero);
    check(!alternative.prepared && alternative.excluded_events==std::vector<std::string>{"17:bankruptcy_flow_required","13:event_tile_color_mismatch"},"red never falls back to a good event");
    policy.entries={{2,1}}; human.synthetic_actor=true; human.static_type=68;
    check(!prepare_richonline_chance_landing(table,resources,rules,policy,human,99,funds,inventory,zero).prepared,"boss does not gain card");
    policy.entries={{27,1}}; human.synthetic_actor=false; human.static_type=69;
    const auto unclosed=prepare_richonline_chance_landing(table,resources,rules,policy,human,99,funds,inventory,zero);
    check(!unclosed.prepared && unclosed.excluded_events[0]=="27:event_followup_not_closed","sleep flow not falsely enabled");
    human.actor_status.sleepwalking=2;
    check(prepare_richonline_chance_landing(table,resources,rules,policy,human,99,funds,inventory,zero).disposition==RichonlineChanceLandingDisposition::not_applicable,"client bypass status");
    human.actor_status={};policy.entries={{13,1}}; human.static_type=68;
    rejects([&]{prepare_richonline_chance_landing(table,resources,rules,policy,human,99,funds,inventory,[](std::size_t n){return n;});});
    policy.entries={{13,1},{2,1}}; funds.funds.deposit.reset();
    rejects([&]{prepare_richonline_chance_landing(table,resources,rules,policy,human,99,funds,inventory,zero);},"money_snapshot_unavailable");
    funds.funds.deposit=0; inventory[0]={-1,1};
    rejects([&]{prepare_richonline_chance_landing(table,resources,rules,policy,human,99,funds,inventory,zero);},"richonline_chance_landing_inventory_invalid");
    inventory[0]={1038,1}; human.actor_status.turtle=128;
    rejects([&]{prepare_richonline_chance_landing(table,resources,rules,policy,human,99,funds,inventory,zero);},"richonline_chance_landing_status_invalid");
    human.actor_status.turtle=2; policy.entries={{25,1},{12,1}}; human.static_type=70;
    const auto conflict=prepare_richonline_chance_landing(table,resources,rules,policy,human,99,funds,inventory,zero);
    check(conflict.prepared && conflict.prepared->event==12 && conflict.excluded_events==std::vector<std::string>{"25:motion_priority_unverified"},"unproven six/turtle precedence excluded");
    human.actor_status={};policy.map_name="map";policy.entries={{0,1},{1,1}}; human.static_type=68;
    rejects([]{RichonlineChanceEventTable::parse("map\t2\t0\t0\t0\t-1\t1\t,\ti\t%d\nmap\t2\t0\t0\t0\t1\t1\t,\ti\t%d");},"richonline_chance_event_number_invalid");
    const auto invalid_format=RichonlineChanceEventTable::parse("map\t2\t1\t0\t0\t1\t1\t,\ti\t%n\nmap\t2\t1\t0\t0\t1\t1\t,\ti\t%d");
    rejects([&]{prepare_richonline_chance_landing(invalid_format,resources,rules,policy,human,99,funds,inventory,zero);});
    const auto invalid_candidates=RichonlineChanceEventTable::parse("map\t5\t1\t0\t0\t1\t1\tx1038\ti\t%d\nmap\t2\t1\t0\t0\t1\t1\t,\ti\t%d");
    rejects([&]{prepare_richonline_chance_landing(invalid_candidates,resources,rules,policy,human,99,funds,inventory,zero);},"richonline_chance_landing_candidate_invalid");
}
void color_pools(const std::filesystem::path& root) {
    const auto table=RichonlineChanceEventTable::load(root);
    const auto resources=RichonlineChanceResources::load(root);
    const auto rules=RichonlineStatusRules::load(root);
    const RichonlineGameFundsSnapshot funds{{1000000,1000000,350,{}},7};
    RichonlineChanceInventory inventory{}; inventory[0]={1038,3};
    for(const auto map:{"BS_1_1.emp","V_BS_1_1.emp"}) {
        auto policy=make_richonline_closed_chance_policy(table,map,{1038,1039,1040,1041},true,{0,0});
        for(std::int8_t tile=68;tile<=70;++tile) {
            const auto column=static_cast<std::size_t>(tile-68);
            RichonlineLandingContext context{0,100,tile,-1,3,false,3,false,{}};
            bool gain=false,loss=false,motion=false;
            for(std::size_t i=0;i<table.size(map);++i) {
                const auto& event=table.event(map,static_cast<std::int32_t>(i));
                if(event.category>9) continue;
                policy.entries={{event.id,1}};
                std::size_t calls=0;
                const auto result=prepare_richonline_chance_landing(table,resources,rules,policy,context,99,funds,inventory,
                    [&](std::size_t) {++calls;return std::size_t{0};});
                if(event.raw_weights[column]==0) {
                    check(!result.prepared && calls==0 && result.excluded_events==std::vector<std::string>{std::to_string(event.id)+":event_tile_color_mismatch"},"wrong color filtered before RNG and preparation");
                } else if(result.prepared) {
                    const bool good=event.category>=2 && event.category<=5;
                    const bool bad=event.category<=1 || event.category==6;
                    check(tile!=68 || good,"blue selected bad event");
                    check(tile!=69 || bad,"red selected good event");
                    gain=gain || good;loss=loss || bad;motion=motion || event.category>=7;
                }
            }
            check(tile==68 ? gain && !loss && !motion : tile==69 ? loss && !gain && !motion : gain && loss && motion,"color pool coverage");
        }
        policy=make_richonline_closed_chance_policy(table,map,{1038,1039,1040,1041},true,{0,0});
        RichonlineLandingContext poor{0,100,69,-1,3,false,3,false,{}};
        poor.actor_status.turtle=2;
        const RichonlineGameFundsSnapshot empty_funds{{0,0,0,{}},7};
        const RichonlineChanceInventory empty_inventory{};
        const auto no_assets=prepare_richonline_chance_landing(table,resources,rules,policy,poor,99,empty_funds,empty_inventory,
            [](std::size_t n) {return n-1;});
        check(no_assets.prepared && no_assets.prepared->category==6 && no_assets.prepared->updated_inventory==empty_inventory &&
            no_assets.prepared->updated_funds==empty_funds.funds,"red empty purse and bag closes with original zero-card removal");
    }
}
}
int main(int argc,char** argv) {
    try {if(argc!=2) throw std::runtime_error("expected NEW root"); real_map(argv[1]); color_pools(argv[1]);
        std::cout<<"PASS NEW chance landing closed-candidate policy and immutable shared snapshots\n";
    } catch(const std::exception& error) {std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
