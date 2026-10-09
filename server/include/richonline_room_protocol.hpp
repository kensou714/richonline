#pragma once

// 新版房间线协议：保留固定记录及扩展区，未确认字段使用偏移名。

#include "codec.hpp"

#include <array>

namespace richnet {

// 新版 871720/8A56D0 证据：按偏移命名字段，不把未确认字段猜测成游戏设置。
struct RichonlineRoomDescription {
    std::array<std::uint8_t, 128> record;
    Bytes extension;
    std::uint32_t field(std::size_t offset) const;
};
struct RichonlineRoomEdit {
    std::uint32_t tag;
    RichonlineRoomDescription description;
};

RichonlineRoomDescription decode_richonline_room_create(View payload);
RichonlineRoomEdit decode_richonline_room_edit(View payload);

// 88AFE0 与 887310 本地房间处理流程需要的标识字段。
struct RichonlineRoomIdentity {
    std::uint32_t key;
    std::uint32_t unknown_prefix;
    std::uint32_t actor;
    std::uint32_t slot;
    std::uint32_t object28;
};
Frame richonline_room_record(std::uint32_t wire_type, const RichonlineRoomDescription& description,
                            RichonlineRoomIdentity identity);
}
