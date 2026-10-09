#include "richonline_motion_card.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if(!value) throw std::runtime_error(reason); }
template<class F> void rejects(F action,std::string_view expected) {
    try {action();} catch(const CodecError& error) {if(error.what()==expected) return; throw;}
    throw std::runtime_error("expected_rejection");
}
void run(const std::filesystem::path& root) {
    const auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
    RichonlineBossCards cards(resources,0x1234,{"BS_1_1.emp",17,1038,{0x12,0x34}});
    const auto rules=RichonlineMotionCardRules::load(root);
    check(rules.stay_turns==1 && rules.turtle_turns==3,"real_GValue_duration_wrong");
    const auto map=load_richonline_road_topology(root/"Map"/"BS_1_1.emp");
    const auto chooser=[](std::size_t){return std::size_t{0};};
    RichonlineMotionCardTarget target{0,99,1,{},true,true};
    for(const auto& cell:map.cells()) if(cell.walkable && cell.neighbors[1]) {target.position=cell.position;break;}
    cards.commit_inventory(cards.prepare_add(1041,2));
    const auto req=parse_richonline_motion_card(Bytes{106,0,0x56,0x34,0,0,0,0xcc});
    check(req.opaque7==0xcc && req.calendar_counter==0x3456,"wire_fields_wrong");
    target.status.turtle=3; target.status.one_step=2;
    const auto before=cards.inventory();
    const auto stay=plan_richonline_motion_card(0x1234,req,0x3456,0,target,rules,map,chooser,cards);
    check(stay.response==Bytes{0xba,0x40,0x34,0x12,0,0,0} &&
        stay.continuation==RichonlineMotionCardContinuation::await_same_position17 &&
        stay.after.status.stay==1 && stay.after.status.turtle==0 && stay.after.status.one_step==0 &&
        stay.consumption.remaining_inventory[0]==RichonlineChanceCardSlot{1041,1} && cards.inventory()==before,
        "self_stay_must_reenter_landing_without_moving_or_committing");
    target.status.protected_from_status=true;
    const auto blocked=plan_richonline_motion_card(0x1234,req,0x3456,0,target,rules,map,chooser,cards);
    check(blocked.blocked_by_protection && blocked.after.status==target.status && blocked.recovery &&
        *blocked.recovery==Bytes{0x0b,0x40,0x34,0x12,1} &&
        blocked.continuation==RichonlineMotionCardContinuation::resume_controls,"self_protection_stall");
    target.status.protected_from_status=false;
    auto other=req;other.target_actor=1;target.actor=1;
    const auto other_stay=plan_richonline_motion_card(0x1234,other,0x3456,0,target,rules,map,chooser,cards);
    check(other_stay.continuation==RichonlineMotionCardContinuation::resume_controls,"other_stay_ended_active_turn");
    cards.commit_consumption(other_stay.consumption);
    rejects([&]{cards.commit_consumption(other_stay.consumption);},"richonline_card_consumption_inventory_changed");
    cards.commit_inventory({});cards.commit_inventory(cards.prepare_add(1039));target.status.stay=1;
    auto turtle=parse_richonline_motion_card(Bytes{104,0,0x56,0x34,0,0,1,0});
    const auto turtle_plan=plan_richonline_motion_card(7,turtle,0x3456,0,target,rules,map,chooser,cards);
    check(turtle_plan.after.status.turtle==3 && turtle_plan.after.status.stay==0,"turtle_did_not_replace_stay");
    cards.commit_inventory({});cards.commit_inventory(cards.prepare_add(1040));
    auto reverse=parse_richonline_motion_card(Bytes{105,0,0x56,0x34,0,0,1,0});
    const auto reversed=plan_richonline_motion_card(7,reverse,0x3456,0,target,rules,map,chooser,cards);
    check(reversed.after.heading==3 && reversed.after.position==target.position &&
        reversed.after.status==target.status,"reverse_moved_actor_or_changed_status");
    bool ambiguous_tested=false;
    for(const auto& cell:map.cells()) {
        for(std::uint8_t heading=0;heading<4;++heading) {
            const auto opposite=static_cast<std::uint8_t>((heading+2U)&3U);
            if(!cell.walkable || cell.neighbors[heading] || cell.neighbors[opposite]) continue;
            unsigned sides=0;for(const auto& neighbor:cell.neighbors) if(neighbor) ++sides;
            if(sides!=2) continue;
            auto ambiguous=target;ambiguous.position=cell.position;ambiguous.heading=heading;
            rejects([&]{plan_richonline_motion_card(7,reverse,0x3456,0,ambiguous,rules,map,chooser,cards);},
                "richonline_motion_reverse_heading_ambiguous");
            ambiguous_tested=true;break;
        }
        if(ambiguous_tested) break;
    }
    check(ambiguous_tested,"actual_map_missing_reverse_rng_fixture");
    target.in_target_selection=false;
    rejects([&]{plan_richonline_motion_card(7,reverse,0x3456,0,target,rules,map,chooser,cards);},"richonline_motion_card_target_invalid");
    target.in_target_selection=true;
    rejects([&]{plan_richonline_motion_card(7,reverse,0,0,target,rules,map,chooser,cards);},"richonline_motion_card_counter_mismatch");
    rejects([&]{parse_richonline_motion_card(Bytes{106,0,0,0,8,0,0,0});},"richonline_motion_card_fields_invalid");
    rejects([&]{parse_richonline_motion_card(Bytes{106,0,0,0,0,1,0,0});},"richonline_motion_card_fields_invalid");
    rejects([&]{parse_richonline_motion_card(Bytes{106,0,0,0,0,0,8,0});},"richonline_motion_card_fields_invalid");
}
}
int main(int argc,char** argv) {
    try {if(argc!=2) throw std::runtime_error("resource_path_required");run(argv[1]);
        std::cout<<"PASS NEW motion-card effects, ownership, self-stay continuation and protection\n";
    } catch(const std::exception& e) {std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}
