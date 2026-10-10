-- 天使卡（资源编号 1059）。本文件是该卡的独立业务入口。
-- C2S 操作号 120；request.payload 是未加密的完整内部报文，包含操作号。
-- 脚下同街区建筑升一级；普通上限沿用客户端语义。
-- Lua 决定请求形状、地产操作和回包；核心准备版本化地产变更，与扣卡共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1059, name = "天使卡", opcode = 120, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 6, "天使卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    core.call("property.prepare", { operation = "grow", levels = 1, own_only = false })
    -- 回显槽位/背包及有符号目标 WORD，确认后客户端按对应卡牌消费者更新建筑。
    return { protocol.inner(0x40C8, request.game_id, request.payload:sub(5)) }
end
return M
