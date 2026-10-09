#include "richonline_ground_card.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* message) { if(!value) throw std::runtime_error(message); }
template<class Action> void rejects(Action action,const char* expected) {
    try { action(); } catch(const CodecError& error) {
        check(std::string(error.what())==expected,error.what()); return;
    }
    throw std::runtime_error("expected_ground_card_rejection");
}
RichonlineGroundCardTurnContext context() {
    return {0x1234,91,0,0,true,true,true,true,true,false,8};
}
RichonlineChanceInventory hand() {
    RichonlineChanceInventory result{};result[3]={507,2};return result;
}
RichonlineGroundCardRequest request() { return {RichonlineGroundCard::banana507,91,3,0,77}; }
RichonlineGroundSnapshot ground() { return {{},14}; }
void parser_and_response_are_exact() {
    const Bytes input{165,0,91,0,3,0,77,0};
    const auto decoded=decode_richonline_ground_card165(input);
    check(decoded.calendar==91 && decoded.inventory_slot==3 && decoded.position==77,"ground_card_parse_wrong");
    const Bytes expected{0xf5,0x40,0x34,0x12,3,0,77,0};
    check(encode_richonline_banana40f5(0x1234,decoded)==expected,"ground_card_response_not_exact");
    for(const Bytes& invalid:{Bytes{165,0,91,0,3,0,77},Bytes{165,0,91,0,3,0,77,0,0}})
        rejects([&]{ static_cast<void>(decode_richonline_ground_card165(invalid)); },"richonline_ground_card_request_length");
    rejects([]{ static_cast<void>(decode_richonline_ground_card165(Bytes{164,0,91,0,3,0,77,0})); },"richonline_ground_card_request_opcode");
    rejects([]{ static_cast<void>(decode_richonline_ground_card165(Bytes{165,0,91,0,255,0,77,0})); },"richonline_ground_card_request_fields_invalid");
    rejects([]{ static_cast<void>(decode_richonline_ground_card165(Bytes{165,0,91,0,8,0,77,0})); },"richonline_ground_card_request_fields_invalid");
    rejects([]{ static_cast<void>(decode_richonline_ground_card165(Bytes{165,0,91,0,3,1,77,0})); },"richonline_ground_card_request_fields_invalid");
    rejects([]{ static_cast<void>(decode_richonline_ground_card165(Bytes{165,0,91,0,3,0,255,255})); },"richonline_ground_card_request_fields_invalid");
}
void success_keeps_roll_phase_for_owner_to_commit() {
    const auto before_hand=hand();const auto before_ground=ground();
    const auto plan=plan_richonline_banana_card(request(),context(),before_hand,before_ground);
    check(plan.expected_inventory==before_hand && plan.expected_ground==before_ground,"ground_card_expected_snapshot_wrong");
    check(plan.after_inventory[3].card_id==507 && plan.after_inventory[3].count==1,"ground_card_not_consumed_once");
    const auto placed=plan.after_ground.find(77);
    check(placed!=plan.after_ground.end() && placed->second==RichonlineGroundObject{30,255,255},"banana_owner_or_npc_wrong");
    check(before_hand[3].count==2 && before_ground.objects.empty(),"ground_card_planner_mutated_input");
    check(plan.response40f5.size()==8,"ground_card_added_unproved_ack");
}
void failures_do_not_produce_a_plan() {
    const auto input_hand=hand();const auto input_ground=ground();
    struct Case { RichonlineGroundCardRequest request; RichonlineGroundCardTurnContext context; RichonlineChanceInventory hand; RichonlineGroundSnapshot ground; const char* error; };
    auto calendar=request();calendar.calendar=90;
    auto wrong_card=hand();wrong_card[3]={506,1};
    auto empty=hand();empty[3]={507,0};
    auto occupied=ground();occupied.objects.emplace(77,RichonlineGroundObject{12,0,3});
    auto invisible=context();invisible.target_visible=false;
    auto actor=context();actor.target_has_actor=true;
    auto static_forbidden=context();static_forbidden.target_static_type=58;
    auto controlled=context();controlled.requesting_actor_can_act=false;
    auto waiting=context();waiting.roll_phase=false;
    auto other=context();other.requesting_actor=1;
    auto nonroad=context();nonroad.target_is_walkable=false;
    for(const Case& test:std::array<Case,11>{{
        {calendar,context(),input_hand,input_ground,"richonline_ground_card_calendar_mismatch"},
        {request(),context(),wrong_card,input_ground,"richonline_ground_card_not_owned"},
        {request(),context(),empty,input_ground,"richonline_ground_card_not_owned"},
        {request(),context(),input_hand,occupied,"richonline_ground_card_target_dynamic_occupied"},
        {request(),invisible,input_hand,input_ground,"richonline_ground_card_target_not_visible"},
        {request(),actor,input_hand,input_ground,"richonline_ground_card_target_actor_occupied"},
        {request(),static_forbidden,input_hand,input_ground,"richonline_ground_card_target_static_forbidden"},
        {request(),controlled,input_hand,input_ground,"richonline_ground_card_actor_controlled"},
        {request(),waiting,input_hand,input_ground,"richonline_ground_card_not_roll_phase"},
        {request(),other,input_hand,input_ground,"richonline_ground_card_not_active_actor"},
        {request(),nonroad,input_hand,input_ground,"richonline_ground_card_target_not_walkable"}
    }}) rejects([&]{ static_cast<void>(plan_richonline_banana_card(test.request,test.context,test.hand,test.ground)); },test.error);
    check(input_hand==hand() && input_ground==ground(),"ground_card_failed_plan_mutated_shared_input");
}
void request_fields_are_revalidated_when_called_directly() {
    auto invalid=request();invalid.inventory_slot=8;
    rejects([&]{ static_cast<void>(plan_richonline_banana_card(invalid,context(),hand(),ground())); },"richonline_ground_card_request_fields_invalid");
    auto off_map=context();off_map.target_is_map_cell=false;
    rejects([&]{ static_cast<void>(plan_richonline_banana_card(request(),off_map,hand(),ground())); },"richonline_ground_card_target_not_walkable");
    auto kind=request();kind.kind=static_cast<RichonlineGroundCard>(1043);
    rejects([&]{ static_cast<void>(plan_richonline_banana_card(kind,context(),hand(),ground())); },"richonline_ground_card_kind_invalid");
    for(const std::int8_t type:{std::int8_t{2},std::int8_t{3},std::int8_t{28},std::int8_t{58},std::int8_t{61}}) {
        auto invalid=context();invalid.target_static_type=type;
        rejects([&]{ static_cast<void>(plan_richonline_banana_card(request(),invalid,hand(),ground())); },"richonline_ground_card_target_static_forbidden");
    }
    auto invalid_actor=context();invalid_actor.requesting_actor=-1;
    rejects([&]{ static_cast<void>(plan_richonline_banana_card(request(),invalid_actor,hand(),ground())); },"richonline_ground_card_actor_invalid");
}
void plan_uses_the_single_ground_owner_and_rejects_stale_commit() {
    RichonlineGroundObjects shared({77,78});
    shared.place(78,RichonlineGroundObject{0,255,255});
    auto inventory=hand();inventory[3].count=1;
    const auto plan=plan_richonline_banana_card(request(),context(),inventory,shared.snapshot());
    check(plan.after_inventory[3]==RichonlineChanceCardSlot{},"last_banana_kept_empty_card_id");
    auto prepared=shared.prepare(plan.expected_ground,plan.after_ground);
    check(shared.matches(prepared) && shared.commit_prepared(prepared),"banana_shared_ground_commit_failed");
    inventory=plan.after_inventory;
    check(shared.snapshot().objects.at(78)==RichonlineGroundObject{0,255,255},"banana_overwrote_unrelated_npc");
    check(!shared.matches(prepared) && !shared.commit_prepared(prepared),"banana_prepared_ground_committed_twice");
    auto repeated=hand();
    rejects([&]{ static_cast<void>(plan_richonline_banana_card(request(),context(),repeated,shared.snapshot())); },"richonline_ground_card_target_dynamic_occupied");
    rejects([&]{ static_cast<void>(shared.prepare(plan.expected_ground,plan.after_ground)); },"richonline_ground_stale");
    check(inventory[3]==RichonlineChanceCardSlot{},"repeat_request_changed_consumed_hand");
}
}
int main() {
    try {
        parser_and_response_are_exact();success_keeps_roll_phase_for_owner_to_commit();
        failures_do_not_produce_a_plan();request_fields_are_revalidated_when_called_directly();
        plan_uses_the_single_ground_owner_and_rejects_stale_commit();
        std::cout << "PASS NEW banana C2S165/S2C40F5 planning and explicit ground authority\n";
    } catch(const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
