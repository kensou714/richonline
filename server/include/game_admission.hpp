#pragma once

// 游戏准入描述：按客户端版本编码和校验连接身份；未确认字段只保留原始值。

#include "codec.hpp"

#include <array>
#include <cstdint>
#include <optional>

namespace richnet {

struct GameAdmission {
    // 此处保留协议字段形状；业务身份映射由各版本 redirect 模块负责。
    std::uint32_t id0{};
    std::uint32_t id1{};
    std::uint32_t id2{};
    std::array<std::uint8_t, 8> opaque8{};
    std::uint32_t field20{};
// 旧版载荷偏移 +24/+28；新版不携带这两个字段。
    std::optional<std::array<std::uint32_t, 2>> legacy_fields;

    bool operator==(const GameAdmission&) const = default;
};

GameAdmission decode_game_admission(const Frame& frame, ClientVersion version);
Frame encode_game_admission(const GameAdmission& admission, ClientVersion version);

}
