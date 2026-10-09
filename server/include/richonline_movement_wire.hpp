#pragma once

// 新版移动线协议：解析回合动作并编码 4010/4011；长度策略须与逆向证据区分。

#include "codec.hpp"
#include <variant>

namespace richnet {
struct RichonlineMoveRequest10 { std::uint16_t calendar_counter; std::uint32_t parameter; };
struct RichonlineMoveStop11 { std::uint16_t calendar_counter; std::int16_t endpoint; };
struct RichonlineMoveCountdown12 { std::uint16_t calendar_counter; std::int16_t endpoint; };
// NEW70B050 sends six bytes. Byte5 is the sender's untouched stack byte,
// retained for diagnostics and never interpreted as part of the count.
struct RichonlineDiceChoice14 { std::uint16_t calendar_counter; std::uint8_t count, opaque5; };
struct RichonlineMovePause28 { std::uint16_t calendar_counter; std::int16_t endpoint; };
struct RichonlineMoveSpecialTile2A { std::uint16_t calendar_counter; std::int16_t endpoint; };
using RichonlineMovementRequest = std::variant<RichonlineMoveRequest10, RichonlineMoveStop11,
    RichonlineMoveCountdown12, RichonlineDiceChoice14, RichonlineMovePause28, RichonlineMoveSpecialTile2A>;

RichonlineMovementRequest parse_richonline_movement_request(View plain);

struct RichonlineTurn4010 {
    std::uint16_t game_server_id;
    std::int8_t actor_slot;
    std::int8_t round_anchor_slot;
    std::uint8_t animation_replay_flag;
};
enum class RichonlineMoveDirection : std::uint8_t { down, left, up, right };
struct RichonlineRoute4011 {
    std::uint16_t game_server_id;
    std::int16_t start_position;
    std::uint8_t dice_count;
    std::array<std::int8_t, 3> ui_dice;
    std::vector<RichonlineMoveDirection> directions;
    // 调用方计算实际消耗步数，包含特殊格子的追加步数。
    // 编解码层只检查路线是否足够长；地图合法性、传送及效果规则仍由调用方负责。
    std::size_t required_route_steps;
};
struct RichonlineRouteWirePolicy {
    std::array<std::uint8_t, 4> opaque20_23;
    std::int32_t local_reserve_charge;
    Bytes optional_tail;
};

// 本地兼容策略：8 字节和 28 字节加显式尾部，不代表历史固定包长。
// 证据：protocol-analysis/richonline-rebuild/game/startup-flow/movement-wire/。
// 未读取的方向位统一置零；尾部长度受客户端 288 字节队列限制。
Bytes encode_richonline_turn4010(const RichonlineTurn4010& turn, std::uint8_t opaque7);
Bytes encode_richonline_route4011(const RichonlineRoute4011& route,
    const RichonlineRouteWirePolicy& policy);
// 使用已确认读取的 6 字节前缀；哨兵值 -1 跳过地图效果，恢复回合阶段 4。
// 调用方必须保证角色没有附加状态；此接口不能跳过状态效果。
Bytes encode_richonline_empty_turn420f(std::uint16_t game_server_id);
}
