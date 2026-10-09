#include "richonline_result_delivery.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if(!value)throw std::runtime_error(reason); }
template<class Action> void rejects(Action action) {
    try { action(); } catch(const CodecError& error) {
        check(std::string_view(error.what())=="richonline_result_display_policy_invalid","wrong_policy_error");return;
    }
    throw std::runtime_error("invalid_policy_accepted");
}
}
int main() {
    try {
        auto now=std::chrono::steady_clock::time_point{};
        const auto clock=[&]{return now;};
        rejects([&]{RichonlineResultDeliveryGate gate({std::chrono::milliseconds{2699},clock});});
        rejects([&]{RichonlineResultDeliveryGate gate({std::chrono::minutes{11},clock});});
        rejects([]{RichonlineResultDeliveryGate gate({std::chrono::milliseconds{6000},{}});});
        RichonlineResultDeliveryGate gate({std::chrono::milliseconds{6000},clock});
        now+=std::chrono::hours{1};
        check(!gate.ready(),"delay_started_before_successful_result_send");
        gate.game_frames_sent();now+=std::chrono::milliseconds{5999};
        check(!gate.ready(),"lobby_return_preempted_result_display");
        gate.game_frames_sent(); // A repeated whole-send observation cannot restart it.
        now+=std::chrono::milliseconds{1};
        check(gate.ready(),"display_deadline_not_reached");
        now+=std::chrono::hours{1};check(gate.ready(),"completed_gate_reverted");
        std::cout<<"result delivery policy passed\n";return 0;
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n';return 1; }
}
