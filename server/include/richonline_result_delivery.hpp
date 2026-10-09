#pragma once

#include "codec.hpp"
#include <chrono>
#include <functional>
#include <optional>

namespace richnet {
// The NEW client sends no result acknowledgement. This is an explicit server
// display policy measured from the last successfully sent game result frame.
struct RichonlineResultDisplayPolicy {
    std::chrono::milliseconds delay;
    std::function<std::chrono::steady_clock::time_point()> now;
};
class RichonlineResultDeliveryGate final {
public:
    explicit RichonlineResultDeliveryGate(RichonlineResultDisplayPolicy);
    void game_frames_sent();
    bool ready() const;
private:
    RichonlineResultDisplayPolicy policy_;
    std::optional<std::chrono::steady_clock::time_point> deadline_;
};
}
