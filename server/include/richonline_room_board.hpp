#pragma once

#include "richonline_board.hpp"
#include "richonline_room_directory.hpp"

#include <span>

namespace richnet {
// 角色和资金始终一起排序；调用者先完成地图、装备及初始资金校验。
struct RichonlineRoomBoardPlayer {
    std::uint64_t connection;
    RichonlineBoardParticipant participant;
    RichonlineBoardBalances balances;
};
struct RichonlineRoomBoardSynthetic {
    RichonlineBoardParticipant participant;
    RichonlineBoardBalances balances;
};
struct RichonlineRoomBoardRecipient {
    std::uint64_t connection;
    RichonlineBoardInit init;
    RichonlineBoardSnapshot snapshot;
};
// 房间槽可能因离房而留空：真人按房间槽升序压紧，再追加合成角色。
// 每份4000仅local_slot不同；4004与角色数组始终共用同一个局内槽顺序。
// 此函数不创建会话，也不决定普通地图的规则或合成角色政策。
std::vector<RichonlineRoomBoardRecipient> build_richonline_room_boards(
    const RichonlineRoomSnapshot& room, RichonlineBoardInit header,
    RichonlineBoardSnapshot snapshot_header,
    std::span<const RichonlineRoomBoardPlayer> players,
    std::span<const RichonlineRoomBoardSynthetic> synthetic = {});
}
