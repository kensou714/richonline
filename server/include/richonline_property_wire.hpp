#pragma once

// 新版购地线协议：解析接受/拒绝请求，响应仅覆盖客户端已确认读取的前缀。

#include "codec.hpp"

namespace richnet {
struct RichonlinePropertyRequest {
    std::uint16_t calendar;
    std::uint32_t secondary;
    bool accept;
    // 发送方未赋值这 3 字节；仅保留原值，不推测含义。
    std::array<std::uint8_t, 3> opaque_tail;
};
RichonlinePropertyRequest decode_richonline_property_request(View plain);
// 输出 0x65e8c0 已确认读取的 5 字节；历史完整包长仍未知。
Bytes richonline_property_response(std::uint16_t game_id, bool accept);
}
