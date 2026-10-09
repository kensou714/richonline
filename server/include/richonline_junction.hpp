#pragma once

// 新版岔路选择：记录允许方向和等待期限，由外层负责角色、连接及阶段校验。

#include "richonline_route.hpp"
#include <chrono>

namespace richnet {
struct RichonlineJunctionRequest {
    std::uint16_t calendar_counter;
    std::int8_t direction;
    std::uint8_t unassigned_padding;
};
RichonlineJunctionRequest decode_richonline_junction_request(View plain);
Bytes encode_richonline_junction_response(std::uint16_t game_server_id,std::int8_t direction);

struct RichonlineJunctionEntry {
    std::int16_t position;
    std::uint8_t heading;
    std::uint16_t calendar_counter;
};
struct RichonlineJunctionResult {
    Bytes response;
    std::uint8_t heading;
};
// 仅在人类角色的静态格子/地产阶段结束后调用。
// 调用方负责角色、连接和阶段校验，且必须在下一条 4010 前提交朝向。
class RichonlineJunction final {
public:
    using Clock=std::chrono::steady_clock;
    explicit RichonlineJunction(std::uint16_t game_server_id):game_id_(game_server_id) {}
    bool begin(const RichonlineRoadTopology& topology,const RichonlineJunctionEntry& entry,Clock::time_point now);
    RichonlineJunctionResult decide(View plain,Clock::time_point now);
    std::optional<RichonlineJunctionResult> poll(Clock::time_point now);
    bool pending() const noexcept { return pending_.has_value(); }
private:
    struct Pending {
        RichonlineJunctionEntry entry;
        std::array<bool,4> permitted;
        Clock::time_point deadline;
    };
    std::uint16_t game_id_;
    std::optional<Pending> pending_;
    RichonlineJunctionResult finish(std::int8_t direction);
};
}
