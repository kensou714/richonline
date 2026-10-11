#pragma once
#include "richonline_classic_trade.hpp"

namespace richnet {
struct RichonlineClassicHotelRules {
    // GValue索引1是原始住店计数，不能用界面“休息一天”硬编码为1。
    std::int8_t stay_turns;
    static RichonlineClassicHotelRules load(const std::filesystem::path& root);
};
struct RichonlineClassicHotelVisit {
    std::int16_t property,road,inside;
    std::uint8_t heading;
    bool operator==(const RichonlineClassicHotelVisit&) const = default;
};
std::uint16_t decode_richonline_classic_hotel_request(View);
RichonlineClassicTradeResult prepare_richonline_classic_hotel(std::uint16_t game_id,
    const RichonlineClassicPropertyState&,std::uint32_t scale,std::int8_t result,
    std::shared_ptr<LuaServer> script={});
// 精确镜像630930的顺序候选写入；不能从道路邻接表猜非道路的饭店内部位置。
RichonlineClassicHotelVisit prepare_richonline_classic_hotel_visit(const RichonlineRoadTopology&,
    std::int16_t road,std::int16_t property,std::shared_ptr<LuaServer> script={});
}
