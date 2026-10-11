-- 恶魔卡（资源编号 1077）。本文件是该卡的独立业务入口。
-- C2S 操作号 134；request.payload 是未加密的完整内部报文，包含操作号。
-- 脚下同街区普通地产表中正等级建筑降一级，包含商店；来源种类8/9/10拒绝。
-- 降至0时住宅kind0、大型地kind-1，产权/计时保留；研发由后续回合按新等级检查。
-- Lua 决定请求形状、地产操作和回包；核心准备版本化地产变更，与扣卡共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1077, name = "恶魔卡", opcode = 134, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 6, "恶魔卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    core.call("property.prepare", { operation = "grow", levels = -1, own_only = false })
    -- 只回显槽位/背包，无目标WORD；客户端按当前位置播放动画24，无独立网络ACK。
    return { protocol.inner(0x40D6, request.game_id, request.payload:sub(5)) }
end
return M
