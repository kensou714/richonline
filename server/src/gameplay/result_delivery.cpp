#include "richonline_result_delivery.hpp"

namespace richnet {
RichonlineResultDeliveryGate::RichonlineResultDeliveryGate(RichonlineResultDisplayPolicy policy)
    :policy_(std::move(policy)) {
    if(!policy_.now || policy_.delay<std::chrono::milliseconds{2700} ||
        policy_.delay>std::chrono::minutes{10})
        throw CodecError("richonline_result_display_policy_invalid");
}
void RichonlineResultDeliveryGate::game_frames_sent() {
    if(!deadline_)deadline_=policy_.now()+policy_.delay;
}
bool RichonlineResultDeliveryGate::ready() const {
    return deadline_ && policy_.now()>=*deadline_;
}
}
