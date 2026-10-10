-- 建屋卡（资源编号 1062）。本文件是该卡的独立业务入口。
-- C2S 操作号 123；request.payload 是未加密的完整内部报文，包含操作号。
-- 目标是棋盘格 position，不是地产引用；需自己拥有并满足等级能力上限。
-- Lua 决定请求形状、地产操作和回包；核心准备版本化地产变更，与扣卡共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1062, name = "建屋卡", opcode = 123, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 8, "建屋卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    local target = string.unpack("<i2", request.payload, 7)
    core.call("property.prepare", { operation = "house", position = target })
    -- 回显槽位/背包及有符号目标 WORD，确认后客户端按对应卡牌消费者更新建筑。
    return { protocol.inner(0x40CB, request.game_id, request.payload:sub(5)) }
end
return M
