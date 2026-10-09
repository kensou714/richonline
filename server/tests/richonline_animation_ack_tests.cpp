#include "richonline_animation_ack.hpp"
#include <iostream>

namespace {
using namespace richnet;
using Gate=RichonlineAnimationAck;
const auto now=Gate::Clock::time_point{};
void check(bool value,const char* reason) { if(!value) throw std::runtime_error(reason); }
template<class F> void rejects(F action,const char* expected) {
    try { action(); } catch(const CodecError& error) {
        check(std::string(error.what())==expected,"unexpected_ack_error");return;
    }
    throw std::runtime_error("expected_ack_rejection");
}
Bytes wire(std::uint16_t counter) {
    return {21,0,static_cast<std::uint8_t>(counter),static_cast<std::uint8_t>(counter>>8)};
}
RichonlineAnimationAckTransition entry(std::uint16_t counter=7,std::uint64_t turn=12,
    RichonlineAckAnimation type=RichonlineAckAnimation::type10,std::uint64_t token=91) {
    return {token,turn,counter,type,type==RichonlineAckAnimation::type6,{0,0,false,false,false},
        now+std::chrono::seconds{5}};
}
RichonlineAnimationAckContext context(std::uint64_t turn=12,std::uint64_t token=91) {
    return {token,turn,{0,0,false,false,false}};
}
void successful_transitions_are_one_shot() {
    for(const auto type:{RichonlineAckAnimation::type6,RichonlineAckAnimation::type10,RichonlineAckAnimation::type12}) {
        Gate gate;auto transition=entry(7,12,type);gate.begin(transition,now);
        const auto result=gate.accept(wire(7),context(),now);
        check(result.disposition==RichonlineAnimationAckDisposition::completed && result.transition &&
            result.transition->token==91 && result.transition->animation==type && !gate.pending(),"wrong_completion");
        const auto duplicate=gate.accept(wire(7),context(),now);
        check(duplicate.disposition==RichonlineAnimationAckDisposition::duplicate && !duplicate.transition,
            "duplicate_released_continuation");
        rejects([&]{gate.begin(entry(7,12,RichonlineAckAnimation::type12),now);},
            "richonline_animation_ack_token");
        gate.begin(entry(7,12,RichonlineAckAnimation::type12,92),now);
        check(gate.accept(wire(7),context(),now).disposition==RichonlineAnimationAckDisposition::duplicate &&
            gate.pending(),"old_server_callback_completed_new_event");
        const auto second=gate.accept(wire(7),context(12,92),now);
        check(second.transition && second.transition->token==92,"same_counter_second_event_rejected");
    }
}
void authority_and_wire_validation_do_not_consume_pending() {
    Gate gate;
    rejects([&]{gate.accept(wire(7),context(),now);},"richonline_animation_ack_unexpected");
    gate.begin(entry(),now);
    rejects([&]{gate.begin(entry(8),now);},"richonline_animation_ack_already_pending");
    for(const auto& packet:{Bytes{},Bytes{21,0,7},Bytes{21,0,7,0,0}})
        rejects([&]{gate.accept(packet,context(),now);},"richonline_animation_ack_size");
    rejects([&]{gate.accept(Bytes{20,0,7,0},context(),now);},"richonline_animation_ack_opcode");
    rejects([&]{gate.accept(wire(8),context(),now);},"richonline_animation_ack_unexpected");
    rejects([&]{gate.accept(wire(7),context(13),now);},"richonline_animation_ack_context_changed");
    auto other=context();other.gates.actor=1;other.gates.local_actor=1;
    rejects([&]{gate.accept(wire(7),other,now);},"richonline_animation_ack_context_changed");
    for(int field=0;field<4;++field) {
        auto invalid=context();
        if(field==0) invalid.gates.actor=1;
        if(field==1) invalid.gates.player552=true;
        if(field==2) invalid.gates.player1488_is7=true;
        if(field==3) invalid.gates.player1499=true;
        rejects([&]{gate.accept(wire(7),invalid,now);},"richonline_animation_ack_local_gate");
    }
    check(gate.pending(),"invalid_ack_consumed_pending");
    check(gate.accept(wire(7),context(),now).transition.has_value(),"valid_retry_failed");
}
void excluded_origins_cannot_register() {
    for(int field=0;field<4;++field) {
        Gate gate;auto invalid=entry();
        if(field==0) invalid.gates.actor=1;
        if(field==1) invalid.gates.player552=true;
        if(field==2) invalid.gates.player1488_is7=true;
        if(field==3) invalid.gates.player1499=true;
        rejects([&]{gate.begin(invalid,now);},"richonline_animation_ack_local_gate");
        gate.begin(entry(),now);
    }
    Gate gate;auto invalid=entry(7,12,RichonlineAckAnimation::type6);invalid.type6_mode1=false;
    rejects([&]{gate.begin(invalid,now);},"richonline_animation_ack_mode");
    invalid=entry();invalid.type6_mode1=true;
    rejects([&]{gate.begin(invalid,now);},"richonline_animation_ack_mode");
    invalid=entry();invalid.animation=static_cast<RichonlineAckAnimation>(1);
    rejects([&]{gate.begin(invalid,now);},"richonline_animation_ack_type");
    invalid=entry();invalid.deadline=now;
    rejects([&]{gate.begin(invalid,now);},"richonline_animation_ack_deadline");
    invalid=entry();invalid.token=0;
    rejects([&]{gate.begin(invalid,now);},"richonline_animation_ack_token");
    check(!gate.pending(),"invalid_registration_mutated_state");
}
void expiry_cancel_and_close_never_complete() {
    for(const bool explicit_poll:{false,true}) {
        Gate gate;gate.begin(entry(),now);
        check(!gate.expire(now+std::chrono::seconds{4}),"early_expiration");
        if(explicit_poll) {
            const auto expired=gate.expire(now+std::chrono::seconds{5});
            check(expired && expired->token==91,"expired_identity_missing");
        }
        const auto result=gate.accept(wire(7),context(),now+std::chrono::seconds{5});
        check(result.disposition==RichonlineAnimationAckDisposition::expired && !result.transition &&
            !gate.pending(),"late_ack_completed");
        rejects([&]{gate.begin(entry(),now);},"richonline_animation_ack_token");
        gate.begin(entry(8,13,RichonlineAckAnimation::type10,92),now);
        check(gate.accept(wire(7),context(),now).disposition==RichonlineAnimationAckDisposition::expired &&
            gate.pending(),"stale_ack_changed_new_pending");
        check(gate.cancel().has_value() && !gate.cancel(),"cancel_not_once");
        gate.begin(entry(9,14,RichonlineAckAnimation::type10,93),now);gate.close();gate.close();
        check(gate.closed() && !gate.pending() && !gate.expire(now+std::chrono::seconds{6}),"close_failed");
        rejects([&]{gate.accept(wire(9),context(14),now);},"richonline_animation_ack_closed");
        rejects([&]{gate.begin(entry(10,15),now);},"richonline_animation_ack_closed");
    }
}
void wrap_and_reuse_require_fresh_event_instances() {
    Gate gate;gate.begin(entry(0xffff,100),now);
    gate.accept(wire(0xffff),context(100),now);
    gate.begin(entry(0,101,RichonlineAckAnimation::type10,92),now);
    const auto stale=gate.accept(wire(0xffff),context(100),now);
    check(stale.disposition==RichonlineAnimationAckDisposition::duplicate && !stale.transition && gate.pending(),
        "previous_counter_completed_wrapped_pending");
    gate.accept(wire(0),context(101,92),now);
    rejects([&]{gate.begin(entry(1,99,RichonlineAckAnimation::type10,93),now);},"richonline_animation_ack_turn_regression");
    gate.begin(entry(0xffff,100+65536,RichonlineAckAnimation::type10,93),now);
    rejects([&]{gate.accept(wire(0xffff),context(100),now);},"richonline_animation_ack_context_changed");
    check(gate.accept(wire(0xffff),context(100+65536,93),now).transition.has_value(),"reused_counter_after_wrap_failed");
}
}
int main() {
    try {
        check(decode_richonline_animation_ack21(wire(0xabcd)).calendar_counter==0xabcd,"calendar_decode_wrong");
        successful_transitions_are_one_shot();authority_and_wire_validation_do_not_consume_pending();
        excluded_origins_cannot_register();expiry_cancel_and_close_never_complete();
        wrap_and_reuse_require_fresh_event_instances();
        std::cout<<"PASS animation ACK21 pending identity, gates, wire, duplicate, expiry, wrap and close\n";
    } catch(const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n';return 1; }
}
