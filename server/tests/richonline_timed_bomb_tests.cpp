#include "richonline_timed_bomb.hpp"
#include <iostream>

namespace {
using namespace richnet;
constexpr auto policy=RichonlineTimedBombContinuationPolicy::timed_bomb_stop_then_landing;
void check(bool ok,const char* why) { if(!ok) throw std::runtime_error(why); }
void rejects(auto action,const char* code) {
    try { action(); } catch(const CodecError& error) { check(std::string(error.what())==code,error.what());return; }
    throw std::runtime_error("expected_timed_bomb_rejection");
}
RichonlineCombatWorld world() {
    RichonlineCombatWorld result;result.width=10;result.height=10;
    result.resources={3000,4000,5000,1000,1500,3,2,1,2,2};return result;
}
RichonlineCombatSessionView state(unsigned count=2) {
    RichonlineCombatSessionView result;result.game_id=7;result.revision=3;
    for(unsigned i=0;i<count;++i) {
        RichonlineCombatActorView actor;actor.slot=static_cast<std::uint8_t>(i);
        actor.position=static_cast<std::int16_t>(10+i);actor.funds={{10000,1000,70,300},2};
        result.actors[i]=actor;
    }
    result.actors[0]->inventory[3]={1045,2};return result;
}
RichonlineTimedBombEligibility raw(unsigned count=2) {
    RichonlineTimedBombEligibility result;
    for(unsigned i=0;i<count;++i) result[i]=RichonlineTimedBombRawEligibility{-1,-1,-1,-1};return result;
}
RichonlineBossCards::PreparedConsumption consumption(const RichonlineCombatSessionView& before) {
    auto after=before.actors[0]->inventory;if(--after[3].count==0) after[3]={};
    return {before.actors[0]->inventory,after,3,1045};
}
RichonlineTimedBombStepContext context(std::int16_t position=10,unsigned count=2) {
    return {0,static_cast<std::uint8_t>(count),position,true,false,raw(count)};
}
void wire_and_resource_bounds() {
    const Bytes bytes{110,0,0x34,0x12,3,0,1,0xcd};const auto request=decode_richonline_timed_bomb110(bytes);
    check(request.calendar_counter==0x1234 && request.inventory_slot==3 && request.target_actor==1 &&
        request.opaque7==0xcd,"110_fields_or_opaque_wrong");
    check(encode_richonline_timed_bomb40be(7,request,0xab)==Bytes({0xbe,0x40,7,0,3,0,1,0xab}),
        "40be_target_byte_or_explicit_envelope_wrong");
    for(std::size_t size=0;size<=10;++size) if(size!=8) {
        auto bad=bytes;bad.resize(size);rejects([&]{decode_richonline_timed_bomb110(bad);},"richonline_timed_bomb_request_length");
    }
    auto bad=bytes;bad[0]=109;rejects([&]{decode_richonline_timed_bomb110(bad);},"richonline_timed_bomb_request_opcode");
    for(const auto [offset,value]:std::array<std::pair<std::size_t,std::uint8_t>,6>{{{4,8},{4,255},{5,1},{5,255},{6,8},{6,255}}}) {
        bad=bytes;bad[offset]=value;rejects([&]{decode_richonline_timed_bomb110(bad);},"richonline_timed_bomb_request_fields_invalid");
    }
    for(const unsigned steps:{1U,127U}) check(RichonlineTimedBombRules::parse("[ITEM]\nindx=0\nvalue="+
        std::to_string(steps)+"\n").movement_steps==steps,"resource_positive_boundary");
    for(const auto* value:{"0","-1","128"}) rejects([&]{RichonlineTimedBombRules::parse(
        std::string("[ITEM]\nindx=0\nvalue=")+value+"\n");},"richonline_timed_bomb_resource_steps_invalid");
    rejects([]{RichonlineTimedBombRules::parse("[ITEM]\nindx=1\nvalue=1\n");},"original_game_value_missing");
    rejects([]{RichonlineTimedBombRules::parse("[ITEM]\nindx=0\nvalue=1\n[ITEM]\nindx=0\nvalue=2\n");},
        "original_game_value_index_duplicate");
}
void attach_exactly_one_with_raw_target_boundaries() {
    auto before=state();const auto w=world();auto eligibility=raw();
    before.actors[1]->status.protected_from_status=true;before.actors[1]->status.safety_helmet_uses=12;
    before.actors[1]->status.timed_bomb=3;before.actors[1]->status.timed_bomb_owner=1;
    before.actors[1]->position=10;
    const RichonlineTimedBombRequest110 request{8,3,0,1,0xcd};
    const auto prepared=consumption(before);
    const auto attach=prepare_richonline_timed_bomb_card(before,w,0,request,8,{20},eligibility,prepared,0xab);
    check(attach.after.actors[0]->inventory[3].count==1 && attach.after.actors[1]->status.timed_bomb==20 &&
        attach.after.actors[1]->status.timed_bomb_owner==0 && attach.after.actors[1]->status.protected_from_status &&
        attach.after.actors[1]->status.safety_helmet_uses==12 && !attach.after.actors[0]->status.timed_bomb &&
        before.actors[0]->inventory[3].count==2 && attach.funds_updates.empty() && attach.card_consumptions.size()==1,
        "attach_not_overwrite_one_unit_or_invented_immunity_transfer");
    for(unsigned field=0;field<4;++field) {
        eligibility=raw();auto& entry=*eligibility[1];
        switch(field) { case 0:entry.actor1493=0;break;case 1:entry.actor1494=0;break;
            case 2:entry.actor1495=0;break;default:entry.actor1497=0;break; }
        rejects([&]{prepare_richonline_timed_bomb_card(before,w,0,request,8,{20},eligibility,prepared,0xab);},
            "richonline_timed_bomb_target_not_authorized");
    }
    eligibility=raw();auto self=request;self.target_actor=0;
    check(prepare_richonline_timed_bomb_card(before,w,0,self,8,{20},eligibility,prepared,0).after.actors[0]->status.timed_bomb==20,
        "self_target_rejected");
    rejects([&]{prepare_richonline_timed_bomb_card(before,w,0,request,9,{20},eligibility,prepared,0);},
        "richonline_timed_bomb_calendar_mismatch");
    auto stale=prepared;stale.source_inventory[3].count=1;
    rejects([&]{prepare_richonline_timed_bomb_card(before,w,0,request,8,{20},eligibility,stale,0);},
        "richonline_timed_bomb_consumption_stale");
    stale=prepared;stale.remaining_inventory[3].count=0;
    rejects([&]{prepare_richonline_timed_bomb_card(before,w,0,request,8,{20},eligibility,stale,0);},
        "richonline_timed_bomb_consumption_invalid");
    before.actors[0]->status.sleepwalking=1;
    rejects([&]{prepare_richonline_timed_bomb_card(before,w,0,request,8,{20},eligibility,prepared,0);},
        "richonline_timed_bomb_action_actor_controlled");
}
void countdown_and_transfer_are_once_per_completed_step() {
    auto before=state(3);const auto w=world();auto step=context(10,3);
    before.actors[0]->status.timed_bomb=3;before.actors[0]->status.timed_bomb_owner=2;
    auto result=prepare_richonline_timed_bomb_step(before,w,step,policy);
    check(result.outcome==RichonlineTimedBombStepOutcome::counted && result.combat.after.actors[0]->status.timed_bomb==2 &&
        result.combat.packets.empty() && result.combat.funds_updates.empty(),"countdown_invented_packets_or_day_clock");
    auto status=before.actors[0]->status;richonline_status_finish_previous_turn(status);
    richonline_status_begin_active_turn(status);richonline_status_begin_combat_phase(status);
    check(status.timed_bomb==3 && status.timed_bomb_owner==2,"turn_hooks_decremented_movement_timer");
    before.actors[1]->position=10;before.actors[2]->position=10;
    before.actors[1]->status.timed_bomb=7;before.actors[1]->status.timed_bomb_owner=-1;
    step.raw[1]->actor1494=3;step.raw[1]->actor1495=5;
    result=prepare_richonline_timed_bomb_step(before,w,step,policy);
    check(result.transferred_to==1 && result.combat.after.actors[0]->status.timed_bomb==7 &&
        result.combat.after.actors[0]->status.timed_bomb_owner==-1 && result.combat.after.actors[1]->status.timed_bomb==2 &&
        result.combat.after.actors[1]->status.timed_bomb_owner==2 && !result.combat.after.actors[2]->status.timed_bomb,
        "transfer_wrong_order_pair_or_extra1494_1495_gate");
    step.raw[1]->actor1497=0;result=prepare_richonline_timed_bomb_step(before,w,step,policy);
    check(result.transferred_to==2,"transfer_1497_not_checked");
    step.raw[1]->actor1497=-1;step.raw[1]->actor1493=0;
    check(prepare_richonline_timed_bomb_step(before,w,step,policy).transferred_to==2,"transfer_1493_not_checked");
    step.raw[1]->actor1493=-1;step.game83830_active=true;
    result=prepare_richonline_timed_bomb_step(before,w,step,policy);
    check(result.combat.after.actors[1]->status.timed_bomb==3,"83830_countdown_or_transfer_wrong");
    step.actor552=false;result=prepare_richonline_timed_bomb_step(before,w,step,policy);
    check(result.outcome==RichonlineTimedBombStepOutcome::unchanged && result.combat.after.revision==before.revision,
        "remote_actor_processed_step");
    step.actor552=true;step.raw[2].reset();
    rejects([&]{prepare_richonline_timed_bomb_step(before,w,step,policy);},"richonline_timed_bomb_raw_eligibility_missing");
    step.raw=raw(3);before.actors[0]->status.timed_bomb_owner.reset();
    rejects([&]{prepare_richonline_timed_bomb_step(before,w,step,policy);},"richonline_timed_bomb_pair_missing");
}
void explosion_mirrors_damage_then_landing_or_terminal() {
    auto before=state();auto w=world();auto step=context();
    before.actors[0]->status.timed_bomb=1;before.actors[0]->status.timed_bomb_owner=1;
    before.actors[0]->status.safety_helmet_uses=15;before.actors[0]->inventory[5]={1076,1};
    before.actors[0]->mine_immune_vehicle=true;before.actors[0]->status.protected_from_status=true;
    unsigned helmets=0;w.helmet=[&](const auto&,const auto&) ->std::optional<RichonlineBossCards::PreparedConsumption> {
        ++helmets;return {};};
    before.dynamic_npcs={{10,11},{12,30},{15,0}};before.mines.mines={{10,1,2}};
    auto explosion=prepare_richonline_timed_bomb_step(before,w,step,policy);
    check(explosion.outcome==RichonlineTimedBombStepOutcome::exploded && explosion.exploding_owner==1 &&
        !explosion.combat.after.actors[0]->status.timed_bomb && !explosion.combat.after.actors[0]->status.timed_bomb_owner &&
        explosion.combat.after.actors[0]->funds.funds.cash==6000 && explosion.combat.funds_updates.size()==1 &&
        explosion.combat.packets==std::vector<Bytes>{{0x13,0x40,7,0,10,0}} &&
        explosion.combat.after.dynamic_npcs.size()==2 && explosion.combat.after.mines==before.mines &&
        explosion.combat.after.actors[0]->inventory==before.actors[0]->inventory && helmets==0 &&
        explosion.combat.after.actors[0]->status.safety_helmet_uses==15,"explosion_double_damaged_or_removed_wrong_state");
    validate_richonline_timed_bomb_ack12(explosion,{9,10},9);
    rejects([&]{validate_richonline_timed_bomb_ack12(explosion,{8,10},9);},"richonline_timed_bomb_ack_calendar_mismatch");
    rejects([&]{validate_richonline_timed_bomb_ack12(explosion,{9,11},9);},"richonline_timed_bomb_ack_position_mismatch");
    auto no_bomb=prepare_richonline_timed_bomb_step(explosion.combat.after,w,step,policy);
    rejects([&]{validate_richonline_timed_bomb_ack12(no_bomb,{9,10},9);},"richonline_timed_bomb_ack_without_explosion");
    bool failed=false;check(!commit_richonline_combat_plan(explosion.combat,[&](const auto&) {failed=true;return false;}) &&
        failed && !explosion.combat.committed,"failed_cas_marked_commit");
    check(commit_richonline_combat_plan(explosion.combat,[](const auto&){return true;}),"successful_cas_rejected");
    rejects([&]{validate_richonline_timed_bomb_ack12(explosion,{9,10},9);},"richonline_timed_bomb_ack_without_explosion");
    before.actors[0]->funds.funds.cash=100;before.actors[0]->funds.funds.deposit=3900;
    explosion=prepare_richonline_timed_bomb_step(before,w,step,policy);
    check(explosion.combat.bankrupt_actors==std::vector<std::uint8_t>{0} && explosion.combat.packets.empty() &&
        explosion.combat.after.actors[0]->funds.funds.cash==0 && *explosion.combat.after.actors[0]->funds.funds.deposit==0,
        "bankrupt_actor_landed_or_cash_deposit_wrong");
    before.actors[0]->funds.funds.cash=20000;before.actors[1]->status.attack_turns=2;
    before.actors[1]->status.attack_multiplier=2.0F;
    check(prepare_richonline_timed_bomb_step(before,w,step,policy).combat.after.actors[0]->funds.funds.cash==12000,
        "owner_modifier_not_used");
    before.actors[1]->active=false;
    check(prepare_richonline_timed_bomb_step(before,w,step,policy).combat.after.actors[0]->funds.funds.cash==16000,
        "inactive_owner_attack_modifier_enabled");
    before.actors[0]->status.timed_bomb_owner=-1;
    check(prepare_richonline_timed_bomb_step(before,w,step,policy).exploding_owner==std::int8_t{-1},"neutral_owner_lost");
}
void actual_resources(const std::filesystem::path& root) {
    const auto rules=RichonlineTimedBombRules::load(root);
    check(rules.movement_steps>=1 && rules.movement_steps<=127,"actual_gvalue0_invalid");
    std::cout<<"NEW GValue[0] carried_bomb_movement_steps="<<unsigned(rules.movement_steps)<<'\n';
}
void segment_projects_until_first_explosion_in_one_transaction() {
    auto before=state();const auto w=world();before.actors[1]->position=90;
    before.actors[0]->status.timed_bomb=3;before.actors[0]->status.timed_bomb_owner=0;
    before.actors[0]->status.attack_turns=2;before.actors[0]->status.attack_multiplier=1.5F;
    const std::array steps{context(11),context(12),context(13),context(14)};
    const auto segment=prepare_richonline_timed_bomb_segment(before,w,0,steps,policy);
    check(segment.accepted_steps==3 && segment.actual_stop==13 && segment.exploding_owner==0 &&
        segment.outcomes==std::vector<RichonlineTimedBombStepOutcome>{RichonlineTimedBombStepOutcome::counted,
            RichonlineTimedBombStepOutcome::counted,RichonlineTimedBombStepOutcome::exploded} &&
        segment.combat.expected.actors[0]->position==10 && segment.combat.after.actors[0]->position==13 &&
        segment.combat.expected.actors[0]->status.timed_bomb==3 && !segment.combat.after.actors[0]->status.timed_bomb &&
        segment.combat.after.actors[0]->funds.funds.cash==4000 && segment.combat.after.revision==before.revision+1 &&
        segment.combat.after.actors[0]->funds.revision==before.actors[0]->funds.revision+1 &&
        segment.combat.funds_updates.size()==1 && segment.combat.funds_updates[0].before==before.actors[0]->funds &&
        segment.combat.packets==std::vector<Bytes>{{0x13,0x40,7,0,13,0}},"segment_not_one_original_cas_or_self_damage_wrong");
    validate_richonline_timed_bomb_segment_ack12(segment,{9,13},9);
    rejects([&]{validate_richonline_timed_bomb_segment_ack12(segment,{9,14},9);},"richonline_timed_bomb_ack_position_mismatch");
    check(before.actors[0]->status.timed_bomb==3 && before.actors[0]->funds.funds.cash==10000,
        "speculative_segment_mutated_original");
    const auto empty=prepare_richonline_timed_bomb_segment(before,w,0,{},policy);
    check(empty.accepted_steps==0 && empty.actual_stop==10 && !empty.exploding_owner && empty.outcomes.empty() &&
        empty.combat.after.revision==before.revision && empty.combat.after.actors[0]->status.timed_bomb==3 &&
        empty.combat.packets.empty(),"zero_steps_decremented_or_exploded");
    rejects([&]{validate_richonline_timed_bomb_segment_ack12(empty,{9,10},9);},"richonline_timed_bomb_ack_without_explosion");
    std::vector<RichonlineTimedBombStepContext> too_many(37,context(11));
    rejects([&]{prepare_richonline_timed_bomb_segment(before,w,0,too_many,policy);},"richonline_timed_bomb_segment_steps_invalid");
    auto wrong=steps;wrong[1].moving_actor=1;
    rejects([&]{prepare_richonline_timed_bomb_segment(before,w,0,wrong,policy);},"richonline_timed_bomb_segment_actor_mismatch");
    before.actors[0]->status.timed_bomb=36;const auto normal=prepare_richonline_timed_bomb_segment(before,w,0,steps,policy);
    check(normal.accepted_steps==4 && !normal.exploding_owner && normal.combat.after.actors[0]->status.timed_bomb==32 &&
        normal.combat.after.revision==before.revision+1 && normal.combat.funds_updates.empty(),"normal_segment_countdown_wrong");
    rejects([&]{validate_richonline_timed_bomb_segment_ack12(normal,{9,14},9);},"richonline_timed_bomb_ack_without_explosion");
}
void segment_transfer_projection_changes_later_explosion() {
    auto before=state();auto w=world();before.actors[1]->position=11;
    before.actors[0]->status.timed_bomb=3;before.actors[0]->status.timed_bomb_owner=0;
    const std::array steps{context(11),context(12),context(13)};
    auto moved=prepare_richonline_timed_bomb_segment(before,w,0,steps,policy);
    check(moved.accepted_steps==3 && !moved.exploding_owner && !moved.combat.after.actors[0]->status.timed_bomb &&
        moved.combat.after.actors[1]->status.timed_bomb==2 && moved.combat.after.actors[1]->status.timed_bomb_owner==0,
        "sent_away_bomb_kept_counting_on_mover");
    before.actors[1]->status.timed_bomb=1;before.actors[1]->status.timed_bomb_owner=1;
    moved=prepare_richonline_timed_bomb_segment(before,w,0,steps,policy);
    check(moved.accepted_steps==2 && moved.actual_stop==12 && moved.exploding_owner==1 &&
        moved.combat.after.actors[1]->status.timed_bomb==2 && !moved.combat.after.actors[0]->status.timed_bomb,
        "received_bomb_exploded_same_step_or_transfer_owner_lost");
}
}
int main(int argc,char** argv) {
    try { if(argc!=2) return 2;wire_and_resource_bounds();attach_exactly_one_with_raw_target_boundaries();
        countdown_and_transfer_are_once_per_completed_step();explosion_mirrors_damage_then_landing_or_terminal();
        actual_resources(argv[1]);segment_projects_until_first_explosion_in_one_transaction();
        segment_transfer_projection_changes_later_explosion();
        std::cout<<"PASS NEW110 timer/owner, selector, transfer, explosion and ACK12 contract\n";
    } catch(const std::exception& error) {std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
