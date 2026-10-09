#pragma once

// 新版自有地产线协议：分别解析建筑选择与升级确认，保留未知尾字节。
#include "codec.hpp"

namespace richnet {
struct RichonlineConstructionRequest {
    std::uint16_t calendar;
    std::int8_t selection;
    std::uint8_t opaque_tail;
};
RichonlineConstructionRequest decode_richonline_construction_request(View plain);
Bytes richonline_construction_response(std::uint16_t game_id, std::int8_t resolved_selection);
struct RichonlineUpgradeRequest {
    std::uint16_t calendar;
    bool accept;
    std::uint8_t opaque_tail;
};
RichonlineUpgradeRequest decode_richonline_upgrade_request(View plain);
Bytes richonline_upgrade_response(std::uint16_t game_id, bool accept);
RichonlineConstructionRequest decode_richonline_research_request(View plain);
Bytes richonline_research_response(std::uint16_t game_id,std::int8_t selection);
}
