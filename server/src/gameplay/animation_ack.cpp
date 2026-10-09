#include "richonline_animation_ack.hpp"
#include <utility>

namespace richnet {
namespace {
void require_gates(const RichonlineAnimationAckGates& gates) {
    if(gates.actor>=8 || gates.local_actor>=8 || gates.actor!=gates.local_actor ||
        gates.player552 || gates.player1488_is7 || gates.player1499)
        throw CodecError("richonline_animation_ack_local_gate");
}
}
RichonlineAnimationAck21 decode_richonline_animation_ack21(View plain) {
    if(plain.size()!=4) throw CodecError("richonline_animation_ack_size");
    if(read_le(plain.first(2))!=21) throw CodecError("richonline_animation_ack_opcode");
    return {static_cast<std::uint16_t>(read_le(plain.subspan(2,2)))};
}
void RichonlineAnimationAck::begin(const RichonlineAnimationAckTransition& transition,Clock::time_point now) {
    if(closed_) throw CodecError("richonline_animation_ack_closed");
    if(pending_) throw CodecError("richonline_animation_ack_already_pending");
    require_gates(transition.gates);
    if(transition.animation!=RichonlineAckAnimation::type6 &&
        transition.animation!=RichonlineAckAnimation::type10 &&
        transition.animation!=RichonlineAckAnimation::type12)
        throw CodecError("richonline_animation_ack_type");
    if((transition.animation==RichonlineAckAnimation::type6)!=transition.type6_mode1)
        throw CodecError("richonline_animation_ack_mode");
    if(transition.token==0) throw CodecError("richonline_animation_ack_token");
    if(transition.deadline<=now) throw CodecError("richonline_animation_ack_deadline");
    if(last_turn_ && transition.turn_sequence<*last_turn_)
        throw CodecError("richonline_animation_ack_turn_regression");
    if(registered_.test(transition.calendar_counter))
        throw CodecError("richonline_animation_ack_counter_reuse");
    pending_=transition;
    registered_.set(transition.calendar_counter);
    last_turn_=transition.turn_sequence;
}
RichonlineAnimationAckResult RichonlineAnimationAck::accept(View plain,
    const RichonlineAnimationAckContext& context,Clock::time_point now) {
    if(closed_) throw CodecError("richonline_animation_ack_closed");
    const auto request=decode_richonline_animation_ack21(plain);
    require_gates(context.gates);
    if(completed_.test(request.calendar_counter))
        return {RichonlineAnimationAckDisposition::duplicate,{}};
    if(!pending_ || request.calendar_counter!=pending_->calendar_counter) {
        if(registered_.test(request.calendar_counter))
            return {RichonlineAnimationAckDisposition::expired,{}};
        throw CodecError("richonline_animation_ack_unexpected");
    }
    if(context.turn_sequence!=pending_->turn_sequence || context.gates.actor!=pending_->gates.actor ||
        context.gates.local_actor!=pending_->gates.local_actor)
        throw CodecError("richonline_animation_ack_context_changed");
    if(now>=pending_->deadline) {
        pending_.reset();
        return {RichonlineAnimationAckDisposition::expired,{}};
    }
    auto transition=pending_;
    completed_.set(request.calendar_counter);
    pending_.reset();
    return {RichonlineAnimationAckDisposition::completed,std::move(transition)};
}
std::optional<RichonlineAnimationAckTransition> RichonlineAnimationAck::expire(Clock::time_point now) {
    if(closed_ || !pending_ || now<pending_->deadline) return {};
    return cancel();
}
std::optional<RichonlineAnimationAckTransition> RichonlineAnimationAck::cancel() {
    auto transition=pending_;
    pending_.reset();
    return transition;
}
void RichonlineAnimationAck::close() noexcept {
    pending_.reset();
    closed_=true;
}
}
