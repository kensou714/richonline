#pragma once

#include "richonline_room_board.hpp"
#include "richonline_map_rules.hpp"
#include "richonline_stock_resources.hpp"

namespace richnet {
struct RichonlineClassicPlayer {
    std::uint64_t connection;
    std::int16_t identity;
    std::array<std::uint32_t,32> equipment;
    std::array<std::int8_t,10> skills;
    std::uint8_t opaque_trailing;
};
struct RichonlineClassicStartup {
    RichonlineRoomSnapshot room;
    std::string map_name;
    std::uint32_t wait_seconds,game_months,pawn_gold,category;
    RichonlineRoadTopology topology;
    RichonlinePropertyResources properties;
    RichonlineStockMap stocks;
    std::vector<OriginalCardWeight> card_weights;
    std::vector<std::int16_t> pool_a_ids,pool_b_ids;
    std::vector<RichonlineRoomBoardRecipient> recipients;
    std::vector<RichonlineClassicPlayer> players;
};
// 仅准备mode0的全真人经典局。头部参与者必须为空；实际资金、地产、股票槽来自EMP。
// 不创建回合、不收押金、不发送跳转；生产provider须具备完整会话后才能使用结果。
RichonlineClassicStartup build_richonline_classic_startup(const std::filesystem::path& root,
    const RichonlineRoomSnapshot& room,RichonlineBoardInit header,std::uint32_t calendar,
    std::span<const RichonlineClassicPlayer> players,
    RichonlineMapSpawnPolicy spawn_policy,const std::function<std::size_t(std::size_t)>& random = {});
}
