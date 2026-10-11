#pragma once

#include "richonline_stock.hpp"
#include "original_map.hpp"
#include <filesystem>
#include <string_view>

namespace richnet {
struct RichonlineStockDefinition {
    // 保留Stock.kpd的Big5字节，不在服务端把它误作UTF-8或写入股票成交包。
    std::string name_big5;
    std::uint32_t assets,shares;
    float activity;
};
struct RichonlineStockResources {
    float rise_limit=10.0F,fall_limit=-10.0F;
    // 下标即资源indx；拒绝重复/缺号，不能按资源出现顺序重编号。
    std::vector<RichonlineStockDefinition> definitions;
};
RichonlineStockResources parse_richonline_stock_resources(std::string_view);
RichonlineStockResources load_richonline_stock_resources(const std::filesystem::path& root);
struct RichonlineStockMap {
    bool enabled;
    std::vector<std::uint32_t> configurations;
};
RichonlineStockMap richonline_stock_map(const OriginalEmp&);
struct RichonlineStockHistory {
    std::uint32_t configuration;
    std::array<float,30> prices;
};
struct RichonlineStockOpening {
    // 上层必须先按顺序发送全部开局包，再接受该market的买卖；不要重复发送历史。
    std::shared_ptr<RichonlineStockMarket> market;
    std::vector<Bytes> messages;
};
// 历史由明确的行情策略提供，按地图槽顺序逐项认证。不在这里伪造历史或随机走势。
RichonlineStockOpening prepare_richonline_stock_opening(std::uint16_t game,
    const RichonlineStockResources&,const RichonlineStockMap&,std::span<const RichonlineStockHistory>,
    float previous_index,float current_index,float factor,std::shared_ptr<RichonlineGameLedger>,
    std::shared_ptr<LuaServer> script = {});
}
