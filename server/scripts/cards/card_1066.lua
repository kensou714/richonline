-- 饭店（资源编号 1066）。本文件是该卡的独立业务入口。
-- C2S 操作号 127；request.payload 是未加密的完整内部报文，包含操作号。
-- 经典改造只改变建筑类型，保留等级、产权和现有增益登记。
-- Lua 决定请求形状、地产操作和回包；核心准备版本化地产变更，与扣卡共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1066, name = "饭店", opcode = 127, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 8, "饭店请求长度错误")
    core.call("card.prepare", { card = M.id })
    local target = string.unpack("<i2", request.payload, 7)
    core.call("property.prepare", { operation = "convert_classic", property = target, kind = 4 })
    -- 回显槽位/背包及有符号目标 WORD，确认后客户端按对应卡牌消费者更新建筑。
    return { protocol.inner(0x40CF, request.game_id, request.payload:sub(5)) }
end
return M
