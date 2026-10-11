#pragma once

#include "richonline_game_registry.hpp"
#include "richonline_game_startup.hpp"
#include "richonline_room_board.hpp"

namespace richnet {
using RichonlineRedirectFactory=std::function<RichonlineGameRedirect()>;
// 将业务启动计划绑定到房间中的每条已认证连接。expected和plans使用相同接收者顺序，
// 每份启动数据必须等于资源校验后的棋盘，不能在业务工厂内改变身份、出生点或资金。
// 多人业务应使用make_richonline_shared_startups持有整局状态；本层只装配连接和准入。
// 任一成员失败时清理整批计划；全部授权成功后才交给注册表发布跳转消息。
std::vector<RichonlineGamePlan> bind_richonline_room_game_plans(const RichonlineRoomSnapshot& room,
    std::span<const RichonlineRoomBoardRecipient> expected,std::vector<RichonlineStartupPlan> plans,
    RichonlineBoardEnvelope envelope,const RichonlineRedirectFactory& redirects,
    const RichonlineFrameFiller& filler,const GameLogSink& log={});
}
