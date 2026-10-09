#include "richonline_boss_cards.hpp"
#include "richonline_fixed_step_card.hpp"
#include "richonline_cosmetic_card.hpp"
#include "richonline_boss_session.hpp"

#include <algorithm>
#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
void check(bool value,std::string_view reason) { if (!value) throw std::runtime_error(std::string(reason)); }
template<class Action> void rejects(Action action,std::string_view reason) {
    try { action(); } catch (const CodecError& error) { check(error.what() == reason,error.what()); return; }
    throw std::runtime_error("expected_rejection");
}
RichonlineLandingContext reward_cell(const std::filesystem::path& root,std::int8_t type) {
    const auto map = load_richonline_road_topology(root/"Map"/"BS_1_1.emp");
    for (const auto& cell : map.cells()) {
        const auto degree = std::count_if(cell.neighbors.begin(),cell.neighbors.end(),[](const auto& next) { return next.has_value(); });
        if (cell.walkable && cell.static_type == type && cell.property_ref == -1 && degree >= 1 && degree <= 2)
            return {0,cell.position,cell.static_type,cell.property_ref,3,false,static_cast<std::uint8_t>(degree),false};
    }
    throw std::runtime_error("actual_map_has_no_eligible_chance_cell");
}
RichonlineCardDiceRequest103 use(std::uint8_t slot,std::uint8_t die) {
    return std::get<RichonlineCardDiceRequest103>(parse_richonline_controlled_dice_request(
        Bytes{0x67,0x00,0x68,0x45,slot,0,die,0xa9,0,0,0,0}));
}
RichonlineBossCardPolicy policy() { return {"BS_1_1.emp",17,1038,{0xa5,0x5a}}; }
void ordinary_card_tile_uses_4029_and_preserves_full_inventory(
    const std::shared_ptr<const RichonlineChanceResources>& resources,const RichonlineLandingContext& cell) {
    RichonlineBossCards cards(resources,0xabcd,policy());
    cards.configure_tile_rewards({1038},[](std::size_t){return std::size_t{0};});
    Bytes stop{0x13,0x40,0xcd,0xab}; append_le(stop,static_cast<std::uint16_t>(cell.position),2);
    const std::vector<Bytes> expected{stop,{0x29,0x40,0xcd,0xab,0x0e,0x04}};
    for (std::size_t i=0;i<8;++i) {
        const auto reward=cards.land(cell);
        check(reward && reward->progress==RichonlineLandingProgress::complete && reward->messages==expected,
            "ordinary_card_tile_response_missing_or_wrong");
        check(cards.inventory()[i]==RichonlineChanceCardSlot{1038,1},"ordinary_card_reward_slot_wrong");
    }
    const auto full=cards.inventory();
    const auto overflow=cards.land(cell);
    check(overflow && overflow->progress==RichonlineLandingProgress::complete && overflow->messages==expected &&
        cards.inventory()==full,"full_ordinary_card_tile_did_not_complete");
    const auto prepared=cards.prepare_use(use(3,5));
    check(prepared && prepared->die==5 && prepared->confirmation40b7==Bytes{0xb7,0x40,0xcd,0xab,3,0},
        "ordinary_card_reward_not_usable");
    cards.commit_use(*prepared);
    check(!cards.prepare_use(use(3,5)) && cards.inventory()[2]==full[2] && cards.inventory()[4]==full[4],
        "ordinary_card_use_shifted_or_reused_slot");
    check(cards.land(cell).has_value() && cards.inventory()==full,"ordinary_card_reward_did_not_reuse_hole");
    const auto disabled=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::parse(
        "disabled.emp\t5\t0\t0\t0\t0\t0\t1038\timg\ttext\n",
        "[PROP]\nindx=1038\ntype=CARD\nenable=false\n",""));
    rejects([&] { RichonlineBossCards invalid(disabled,7,{"disabled.emp",0,1038,{0,0}}); },"richonline_chance_card_invalid");
}
void actual_award_then_prepare_and_commit(const std::shared_ptr<const RichonlineChanceResources>& resources,
    const RichonlineLandingContext& cell) {
    RichonlineBossCards cards(resources,0xabcd,policy());
    check(std::all_of(cards.inventory().begin(),cards.inventory().end(),[](const auto& slot) {
        return slot == RichonlineChanceCardSlot{-1,0};
    }),"initial_inventory_not_empty");
    check(!cards.prepare_use(use(0,4)),"unawarded_card_usable");
    const auto awarded = cards.land(cell);
    Bytes stop{0x13,0x40,0xcd,0xab}; append_le(stop,static_cast<std::uint16_t>(cell.position),2);
    check(awarded && awarded->progress == RichonlineLandingProgress::complete &&
        awarded->messages == std::vector<Bytes>{stop,{0x96,0x40,0xcd,0xab,0x11,0,0xa5,0x5a,0x0e,0x04,0,0}} &&
        cards.inventory()[0] == RichonlineChanceCardSlot{1038,1},"actual_reward_wire_or_ledger_wrong");
    const auto before = cards.inventory(); const auto prepared = cards.prepare_use(use(0,6));
    check(prepared && prepared->die == 6 && prepared->confirmation40b7 == Bytes{0xb7,0x40,0xcd,0xab,0,0} &&
        prepared->remaining_inventory[0] == RichonlineChanceCardSlot{-1,0} && cards.inventory() == before,"prepare_consumed_card_early");
    check(cards.prepare_use(use(0,2)).has_value(),"abandoned_prepare_consumed_card");
    cards.commit_use(*prepared);
    check(cards.inventory()[0] == RichonlineChanceCardSlot{-1,0} && !cards.prepare_use(use(0,6)),"commit_or_repeat_use_wrong");
}
void sparse_slots_stay_at_their_original_indices(const std::shared_ptr<const RichonlineChanceResources>& resources,
    const RichonlineLandingContext& cell) {
    RichonlineBossCards cards(resources,0x1234,policy());
    for (unsigned i = 0; i < 3; ++i) check(cards.land(cell).has_value(),"award_missing");
    const auto before = cards.inventory(); const auto prepared = cards.prepare_use(use(1,3));
    check(prepared && prepared->confirmation40b7 == Bytes{0xb7,0x40,0x34,0x12,1,0},"use_slot_identity_wrong");
    cards.commit_use(*prepared);
    check(cards.inventory()[0] == before[0] && cards.inventory()[1] == RichonlineChanceCardSlot{-1,0} &&
        cards.inventory()[2] == before[2] && cards.inventory()[3].card_id == -1,"consumed_hole_compacted");
    check(cards.land(cell).has_value() && cards.inventory() == before,"reward_did_not_reuse_first_hole");
}
void unsupported_contexts_award_nothing(const std::shared_ptr<const RichonlineChanceResources>& resources,
    const RichonlineLandingContext& good) {
    RichonlineBossCards cards(resources,7,policy()); std::vector<RichonlineLandingContext> invalid;
    auto value = good; value.actor_slot = 1; invalid.push_back(value);
    value = good; value.game_mode = 2; invalid.push_back(value);
    value = good; value.synthetic_actor = true; invalid.push_back(value);
    value = good; value.static_type = 10; invalid.push_back(value);
    value = good; value.property_ref = 216; invalid.push_back(value);
    value = good; value.road_degree = 0; invalid.push_back(value);
    value = good; value.road_degree = 5; invalid.push_back(value);
    value = good; value.occupied_by_other_actor = true; invalid.push_back(value);
    value = good; value.position = -1; invalid.push_back(value);
    const auto empty = cards.inventory();
    for (const auto& context : invalid) check(!cards.land(context) && cards.inventory() == empty,"unsupported_landing_awarded");
}
void combination_preflight_preserves_inventory(const std::shared_ptr<const RichonlineChanceResources>& resources,
    const RichonlineLandingContext& cell) {
    const auto combination = std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::parse(
        "combination.emp\t5\t0\t0\t0\t0\t0\t1038\timg\ttext\n",
        "[PROP]\nindx=1038\ntype=CARD\nenable=true\n",
        "[ITEM]\nenable=true\nsrc0=1038,8\ndest=1039\n"));
    RichonlineBossCards cards(combination,7,{"combination.emp",0,1038,{0xa5,0x5a}});
    for (unsigned i = 0; i < 7; ++i) cards.land(cell);
    const auto before = cards.inventory();
    rejects([&] { cards.land(cell); },"richonline_chance_combination_membership_missing");
    check(cards.inventory() == before,"combination_failure_mutated_ledger");
    auto wrong = policy(); wrong.event_id = 15;
    rejects([&] { RichonlineBossCards invalid(resources,7,wrong); },"richonline_chance_category_unsupported");
    rejects([&] { RichonlineBossCards invalid({},7,policy()); },"richonline_boss_card_resources_required");
    wrong = policy(); wrong.card_id = 1039;
    check(RichonlineBossCards(resources,7,wrong).inventory()==RichonlineChanceInventory{},"valid_reward_card_rejected");
    auto request = use(0,1); request.inventory_slot = -1;
    rejects([&] { cards.prepare_use(request); },"richonline_boss_card_request_invalid");
}
void discard_target_and_shared_inventory(const std::shared_ptr<const RichonlineChanceResources>& resources,
    RichonlineLandingContext cell) {
    RichonlineBossCards cards(resources,0x1234,policy());
    cards.commit_inventory(cards.prepare_add(1044,3));
    const auto before=cards.inventory();
    const auto request=parse_richonline_card_discard50(Bytes{50,0,0x56,0x34,0,0xab});
    check(request.calendar_counter==0x3456 && request.opaque5==0xab,"discard_fields_wrong");
    const auto discarded=cards.prepare_discard(request,0);
    check(discarded.confirmation4033==Bytes{0x33,0x40,0x34,0x12,0,0} &&
        discarded.remaining_inventory==RichonlineChanceInventory{} && cards.inventory()==before,"discard_not_deferred_whole_stack");
    const auto mine=parse_richonline_target_card(Bytes{109,0,0x56,0x34,0,0,99,0});
    const auto pending=cards.prepare_target_effect(mine);
    check(pending && pending->remaining_inventory[0]==RichonlineChanceCardSlot{1044,2} && cards.inventory()==before,
        "target_card_consumed_before_effect_resolution");
    check(encode_richonline_mine40bd(0x1234,mine)==Bytes{0xbd,0x40,0x34,0x12,0,0,99,0},"mine_wire_wrong");
    cards.commit_target_effect(*pending);
    rejects([&] { cards.commit_target_effect(*pending); },"richonline_target_card_inventory_changed");
    cards.commit_inventory(cards.prepare_add(1046));
    const auto missile=parse_richonline_target_card(Bytes{111,0,0x56,0x34,1,0,99,0,0,1});
    check(cards.prepare_target_effect(missile).has_value() &&
        encode_richonline_missile40bf(0x1234,missile,1)==Bytes{0xbf,0x40,0x34,0x12,1,0,99,0,1,0},"missile_wire_or_inventory_wrong");
    rejects([&] {encode_richonline_missile40bf(0x1234,missile,-1);},"richonline_target_card_attacker_invalid");
    check(encode_richonline_missile40bf(0x1234,missile,7)[8]==7,"missile_protocol_has_eight_actor_slots");
    rejects([&] {encode_richonline_missile40bf(0x1234,missile,8);},"richonline_target_card_attacker_invalid");
    rejects([&] {parse_richonline_target_card(Bytes{111,0,0,0,1,0,99,0,0,0});},"richonline_target_card_constructor_invalid");
    rejects([&] {parse_richonline_card_discard50(Bytes{50,0,0,0,8,0});},"richonline_card_discard_slot_invalid");
    rejects([&] {parse_richonline_target_card(Bytes{109,0,0,0,8,0,99,0});},"richonline_target_card_request_invalid");
    rejects([&] {parse_richonline_target_card(Bytes{109,0,0,0,0,1,99,0});},"richonline_target_card_request_invalid");
    rejects([&] {parse_richonline_target_card(Bytes{109,0,0,0,0,0,255,255});},"richonline_target_card_request_invalid");
    rejects([&] {parse_richonline_target_card(Bytes{109,0,0,0,0,0,99});},"richonline_target_card_wire_invalid");
    check(parse_richonline_target_card(Bytes{109,0,255,255,7,0,255,127}).target==32767,
        "wire_parser_must_not_invent_map_bounds");
    cards.commit_inventory({}); cell.static_type=41;
    const auto mine_reward=cards.land(cell);
    check(mine_reward && mine_reward->messages[1]==Bytes{0x29,0x40,0x34,0x12,0x14,4} &&
        cards.inventory()[0]==RichonlineChanceCardSlot{1044,1},"mine_tile_reward_wrong");
    cell.static_type=42; cards.land(cell);
    check(cards.inventory()[1]==RichonlineChanceCardSlot{1046,1},"missile_tile_reward_wrong");
    const auto human_inventory=cards.inventory(); cell.synthetic_actor=true; cell.actor_slot=1;
    check(!cards.land(cell) && cards.inventory()==human_inventory,"synthetic_boss_received_card");
    cards.commit_inventory({}); cards.commit_inventory(cards.prepare_add(1038,2));
    const auto controlled=cards.prepare_use(use(0,2));
    check(controlled && controlled->remaining_inventory[0]==RichonlineChanceCardSlot{1038,1},"stacked_dice_consumed_whole_stack");
}
void full_capacity_reports_reward_without_mutating_inventory(const RichonlineLandingContext& cell) {
    const auto isolated = std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::parse(
        "capacity.emp\t5\t0\t0\t0\t0\t0\t1038\timg\ttext\n",
        "[PROP]\nindx=1038\ntype=CARD\nenable=true\n",""));
    RichonlineBossCards cards(isolated,7,{"capacity.emp",0,1038,{0xa5,0x5a}});
    for (unsigned i = 0; i < 8; ++i) cards.land(cell);
    const auto before = cards.inventory();
    const auto full = cards.land(cell);
    check(full && full->progress == RichonlineLandingProgress::complete && full->messages.size() == 2 &&
        full->messages[1] == Bytes{0x96,0x40,7,0,0,0,0xa5,0x5a,0x0e,0x04,0,0} && cards.inventory() == before,
        "full_inventory_reward_failed_or_mutated_ledger");
}
void fixed_step_cards(const std::shared_ptr<const RichonlineChanceResources>& resources) {
    RichonlineBossCards cards(resources,0xabcd,{"BS_1_1.emp",17,1038,{0x12,0x34}});
    for(std::uint8_t opcode=137;opcode<=140;++opcode) {
        cards.commit_inventory({});
        const auto card=static_cast<std::int16_t>(opcode+943);
        cards.commit_inventory(cards.prepare_add(card,2));
        const auto request=parse_richonline_fixed_step_card(Bytes{opcode,0,0x34,0x12,0,0});
        const auto before=cards.inventory();
        const auto plan=plan_richonline_fixed_step_card(0xabcd,request,0x1234,cards);
        check(plan.steps==opcode-135 && plan.confirmation==Bytes{static_cast<std::uint8_t>(opcode+0x50),0x40,0xcd,0xab,0,0} &&
            plan.consumption.remaining_inventory[0]==RichonlineChanceCardSlot{card,1} && cards.inventory()==before,
            "fixed_step_wrong_card_steps_or_confirmation");
        rejects([&]{plan_richonline_fixed_step_card(1,request,0,cards);},"richonline_fixed_step_card_calendar_mismatch");
        cards.commit_consumption(plan.consumption);
        rejects([&]{cards.commit_consumption(plan.consumption);},"richonline_card_consumption_inventory_changed");
    }
    rejects([&]{parse_richonline_fixed_step_card(Bytes{137,0,0,0,0,1});},"richonline_fixed_step_card_fields_invalid");
    rejects([&]{parse_richonline_fixed_step_card(Bytes{136,0,0,0,0,0});},"richonline_fixed_step_card_fields_invalid");
    rejects([&]{parse_richonline_fixed_step_card(Bytes{137,0,0,0,0,0,0});},"richonline_fixed_step_card_wire_invalid");
}
void cosmetic_cards(const std::shared_ptr<const RichonlineChanceResources>& resources) {
    RichonlineBossCards cards(resources,0xabcd,{"BS_1_1.emp",17,1038,{0x12,0x34}});
    for(const auto opcode:{154,168}) {
        const auto card=static_cast<std::int16_t>(opcode==154 ? 1127 : 1131);
        cards.commit_inventory({});cards.commit_inventory(cards.prepare_add(card,2));
        const auto r=parse_richonline_cosmetic_card(Bytes{static_cast<std::uint8_t>(opcode),0,0x34,0x12,0,0});
        const auto before=cards.inventory();
        const auto plan=plan_richonline_cosmetic_card(0xabcd,r,0x1234,cards);
        check(plan.response==Bytes{static_cast<std::uint8_t>(opcode+0x50),0x40,0xcd,0xab,0,0} &&
            plan.consumption.remaining_inventory[0]==RichonlineChanceCardSlot{card,1} && cards.inventory()==before,
            "cosmetic_card_projection_or_inventory");
        rejects([&]{plan_richonline_cosmetic_card(1,r,0,cards);},"richonline_cosmetic_card_calendar_mismatch");
        cards.commit_consumption(plan.consumption);
        rejects([&]{cards.commit_consumption(plan.consumption);},"richonline_card_consumption_inventory_changed");
    }
    rejects([&]{parse_richonline_cosmetic_card(Bytes{154,0,0,0,0,1});},"richonline_cosmetic_card_fields_invalid");
    rejects([&]{parse_richonline_cosmetic_card(Bytes{153,0,0,0,0,0});},"richonline_cosmetic_card_fields_invalid");
    rejects([&]{parse_richonline_cosmetic_card(Bytes{154,0,0,0,0,0,0});},"richonline_cosmetic_card_wire_invalid");
}
void card_tile_random_resource_pool(const std::shared_ptr<const RichonlineChanceResources>& resources,
    const RichonlineLandingContext& cell) {
    RichonlineBossCards cards(resources,0xabcd,policy());
    rejects([&]{cards.land(cell);},"richonline_card_tile_policy_required");
    std::size_t selected=0,calls=0;
    cards.configure_tile_rewards({1038,1039,1040,1041},[&](std::size_t bound){
        check(bound==4,"ordinary card pool unexpectedly changed");++calls;return selected;
    });
    check(cards.tile_reward_cards()==std::vector<std::int16_t>({1038,1039,1040,1041}),"actual map/Prop reward pool wrong");
    for(selected=0;selected<4;++selected) {
        cards.commit_inventory({});
        const auto result=cards.land(cell);const auto card=static_cast<std::int16_t>(1038+selected);
        check(result&&result->messages.size()==2&&read_le(View(result->messages[1]).subspan(4,2))==static_cast<std::uint32_t>(card)&&
            cards.inventory()[0]==RichonlineChanceCardSlot{card,1},"selected tile card not reflected in packet and inventory");
        const auto use=cards.prepare_consumption(0,card);check(use.has_value(),"random reward unusable inventory");cards.commit_consumption(*use);
    }
    check(calls==4,"tile random was not drawn once per landing");
    const auto before=cards.inventory();selected=4;
    rejects([&]{cards.land(cell);},"richonline_card_tile_random_invalid");check(cards.inventory()==before,"invalid RNG consumed inventory");
    rejects([&]{cards.configure_tile_rewards({1038,1038},[](std::size_t){return std::size_t{0};});},"richonline_card_tile_policy_invalid");
    rejects([&]{cards.configure_tile_rewards({1038},{});},"richonline_card_tile_random_required");
    std::cout<<"Actual BS_1_1 random tile pool: 1038 1039 1040 1041\n";
}
void card_tile_filters_disabled_foreign_and_unsafe_combinations(const RichonlineLandingContext& cell) {
    const auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::parse(
        "tile.emp\t5\t0\t0\t0\t0\t0\t1038\timg\ttext\n",
        "[PROP]\nindx=1038\ntype=CARD\nenable=true\n[PROP]\nindx=1039\ntype=CARD\nenable=true\n"
        "[PROP]\nindx=1040\ntype=CARD\nenable=true\n[PROP]\nindx=1041\ntype=CARD\nenable=false\n"
        "[PROP]\nindx=1042\ntype=CARD\nenable=true\n",
        "[ITEM]\nenable=true\nsrc0=1038,2\ndest=1040\n",{{"tile.emp",{1038,1039,1040,1041}}}));
    RichonlineBossCards cards(resources,7,{"tile.emp",0,1038,{0,0}});
    std::size_t bound_seen=0;
    cards.configure_tile_rewards({1038,1039,1041,1042,9999},[&](std::size_t bound){bound_seen=bound;return std::size_t{0};});
    check(cards.tile_reward_cards()==std::vector<std::int16_t>({1038,1039}),"disabled/map-foreign/unknown cards included");
    cards.commit_inventory(cards.prepare_add(1038));
    const auto result=cards.land(cell);
    check(result&&bound_seen==1&&read_le(View(result->messages[1]).subspan(4,2))==1039&&
        cards.inventory()[0].card_id==1038&&cards.inventory()[1].card_id==1039,"unsafe synthesized reward entered lottery");
    cards.configure_tile_rewards({1038},[](std::size_t){return std::size_t{0};});const auto before=cards.inventory();
    rejects([&]{cards.land(cell);},"richonline_card_tile_no_safe_reward");check(cards.inventory()==before,"no safe candidate mutated inventory");
    rejects([&]{cards.configure_tile_rewards({1041,1042},[](std::size_t){return std::size_t{0};});},"richonline_card_tile_pool_empty");
}
void random_card_tile_full_session(const std::filesystem::path& root,
    const std::shared_ptr<const RichonlineChanceResources>& resources,const RichonlineLandingContext& cell) {
    const auto& package=legacy_richonline_map_package();const auto stage=package.load_stage(root,0);
    const auto topology=load_richonline_road_topology(root/"Map"/stage.map_name);
    std::optional<std::pair<std::int16_t,std::uint8_t>> start;
    for(const auto& candidate:topology.cells()) if(candidate.walkable)
        for(std::uint8_t direction=0;direction<4;++direction)
            if(candidate.neighbors[direction]==cell.position) start={{candidate.position,direction}};
    check(start.has_value(),"card tile has no entry neighbor");
    RichonlineBossStartup startup{{3,25,{},{{1,25,0,true}}},
        {0x1234,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
            {{25,start->first,start->second,{5,5,5,5,5,5,5,5,5,5},0xb1},{-1,236,1,{},0xc1}}},
        {0x1234,0x4567,1,{{20000,0,150},{100000,0,0}}},{7,-2}};
    startup.room.description.record[36]=3;auto& extension=startup.room.description.extension;extension.resize(88);
    std::copy(stage.map_name.begin(),stage.map_name.end(),extension.begin());std::copy(stage.signature.begin(),stage.signature.end(),extension.begin()+32);
    bool reward_draw=false;
    RichonlineBossSessionPolicy session_policy{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
        [&](std::size_t bound){if(bound==4){reward_draw=true;return std::size_t{1};}return std::size_t{0};},policy()};
    auto plan=make_richonline_boss_session(root,startup,package,session_policy,resources,{});
    const auto request=[](std::uint16_t opcode,std::uint16_t calendar,std::uint32_t value,std::size_t width=2){
        Bytes p;append_le(p,opcode,2);append_le(p,calendar,2);append_le(p,value,width);return p;
    };
    plan.map_ready();plan.action({},request(0x11,0x4568,235));plan.action({},request(0x10,0x4569,0,4));
    const auto landed=plan.action({},request(0x11,0x4569,static_cast<std::uint16_t>(cell.position)));
    const auto found=std::find_if(landed.begin(),landed.end(),[](const auto& p){return read_le(View(p).first(2))==0x4029;});
    check(reward_draw&&found!=landed.end()&&read_le(View(*found).subspan(4,2))==1039,"real session ignored card tile RNG");
    plan.action({},request(0x11,0x456a,234));
    const auto used=plan.action({},Bytes{104,0,0x6b,0x45,2,0,0,0xa5});
    check(!used.empty()&&read_le(View(used[0]).first(2))==0x40b8,"random turtle award not usable through real session");
    plan.disconnected();
}
}
int main(int argc,char** argv) {
    try {
        check(argc == 2,"resource_path_required"); const std::filesystem::path root(argv[1]);
        const auto resources = std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
        const auto cell = reward_cell(root,68);
        discard_target_and_shared_inventory(resources,cell);
        fixed_step_cards(resources);
        cosmetic_cards(resources);
        actual_award_then_prepare_and_commit(resources,cell); sparse_slots_stay_at_their_original_indices(resources,cell);
        unsupported_contexts_award_nothing(resources,cell); combination_preflight_preserves_inventory(resources,cell);
        full_capacity_reports_reward_without_mutating_inventory(cell);
        const auto ordinary=reward_cell(root,8);
        ordinary_card_tile_uses_4029_and_preserves_full_inventory(resources,ordinary);
        card_tile_random_resource_pool(resources,ordinary);
        card_tile_filters_disabled_foreign_and_unsafe_combinations(ordinary);
        random_card_tile_full_session(root,resources,ordinary);
        unsupported_contexts_award_nothing(resources,ordinary);
        std::cout << "PASS actual chance-card award and deferred controlled-die inventory consumption\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
