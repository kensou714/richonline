#pragma once

#include "codec.hpp"

namespace richnet {
enum class RichonlineStockAction { buy, sell };
struct RichonlineStockRequest {
    RichonlineStockAction action;
    std::uint16_t slot,quantity;
};
// 0200/0201恰好六字节；+2是股票槽，不是日历或游戏实例号。
RichonlineStockRequest decode_richonline_stock_request(View);
}
