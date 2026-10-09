#pragma once

// 新版指定骰点协议：区分卡片请求与付费请求，并编码卡片消耗及骰子恢复通知。

#include "codec.hpp"
#include <variant>

namespace richnet {
struct RichonlineCardDiceRequest103 {
    std::uint16_t calendar_counter;
    std::int8_t inventory_slot;
    std::int8_t inventory_bank;
    std::uint8_t selected_die;
    std::uint8_t opaque7;
};
struct RichonlinePaidDiceRequest22 {
    std::uint16_t calendar_counter;
    std::uint8_t selected_die;
    std::uint8_t opaque5;
};
using RichonlineControlledDiceRequest = std::variant<RichonlineCardDiceRequest103,RichonlinePaidDiceRequest22>;
// 请求 103 仅接受偏移 +8 处已观察到的构造器零值 DWORD；不解释 opaque 字节。
RichonlineControlledDiceRequest parse_richonline_controlled_dice_request(View plain);

struct RichonlineCardUsed40B7 {
    std::uint16_t game_server_id;
    std::int8_t inventory_slot;
    std::int8_t inventory_bank;
};
// 已确认读取的 6 字节前缀；此响应消耗 bank=0 中指定槽位的卡片。
Bytes encode_richonline_card_used40b7(const RichonlineCardUsed40B7& used);
// 已确认读取的 5 字节前缀，enable=1；只对无附加状态的当前本地行动者生效。
Bytes encode_richonline_dice_recovery400b(std::uint16_t game_server_id);
}
