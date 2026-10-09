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
    if(transition.token<=last_token_) throw CodecError("richonline_animation_ack_token");
    if(transition.deadline<=now) throw CodecError("richonline_animation_ack_deadline");
    if(last_turn_ && transition.turn_sequence<*last_turn_)
        throw CodecError("richonline_animation_ack_turn_regression");
    pending_=transition;
    last_token_=transition.token;
    last_turn_=transition.turn_sequence;
}
RichonlineAnimationAckResult RichonlineAnimationAck::accept(View plain,
    const RichonlineAnimationAckContext& context,Clock::time_point now) {
    if(closed_) throw CodecError("richonline_animation_ack_closed");
    const auto request=decode_richonline_animation_ack21(plain);
    require_gates(context.gates);
    if(retired_ && context.event_token==retired_->transition.token &&
        context.turn_sequence==retired_->transition.turn_sequence &&
        context.gates.actor==retired_->transition.gates.actor &&
        context.gates.local_actor==retired_->transition.gates.local_actor &&
        request.calendar_counter==retired_->transition.calendar_counter)
        return {retired_->disposition,{}};
    if(!pending_) throw CodecError("richonline_animation_ack_unexpected");
    if(context.event_token!=pending_->token)
        throw CodecError("richonline_animation_ack_context_changed");
    if(request.calendar_counter!=pending_->calendar_counter)
        throw CodecError("richonline_animation_ack_unexpected");
    if(context.turn_sequence!=pending_->turn_sequence || context.gates.actor!=pending_->gates.actor ||
        context.gates.local_actor!=pending_->gates.local_actor)
        throw CodecError("richonline_animation_ack_context_changed");
    if(now>=pending_->deadline) {
        cancel();
        return {RichonlineAnimationAckDisposition::expired,{}};
    }
    auto transition=pending_;
    retired_=Retired{*pending_,RichonlineAnimationAckDisposition::duplicate};
    pending_.reset();
    return {RichonlineAnimationAckDisposition::completed,std::move(transition)};
}
std::optional<RichonlineAnimationAckTransition> RichonlineAnimationAck::expire(Clock::time_point now) {
    if(closed_ || !pending_ || now<pending_->deadline) return {};
    return cancel();
}
std::optional<RichonlineAnimationAckTransition> RichonlineAnimationAck::cancel() {
    auto transition=pending_;
    if(pending_) retired_=Retired{*pending_,RichonlineAnimationAckDisposition::expired};
    pending_.reset();
    return transition;
}
void RichonlineAnimationAck::close() noexcept {
    pending_.reset();
    closed_=true;
}
}
