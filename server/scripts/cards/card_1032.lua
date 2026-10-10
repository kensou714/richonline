-- 换地卡（资源编号 1032）。本文件是该卡的独立业务入口。
-- C2S 操作号 97；request.payload 是未加密的完整内部报文，包含操作号。
-- 交换脚下与目标地产的产权，保留建筑；目标为地产引用编号。
-- Lua 决定请求形状、地产操作和回包；核心准备版本化地产变更，与扣卡共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1032, name = "换地卡", opcode = 97, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 8, "换地卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    local target = string.unpack("<i2", request.payload, 7)
    core.call("property.prepare", { operation = "swap", property = target, buildings = false })
    -- 回显槽位/背包及有符号目标 WORD，确认后客户端按对应卡牌消费者更新建筑。
    return { protocol.inner(0x40B1, request.game_id, request.payload:sub(5)) }
end
return M
