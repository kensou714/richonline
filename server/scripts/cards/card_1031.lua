-- 购地卡（资源编号 1031）。本文件是该卡的独立业务入口。
-- C2S 操作号 96；request.payload 是未加密的完整内部报文，包含操作号。
-- 脚下地产购入：产权改变、建筑保留；现金必须严格大于折扣后的地价。
-- Lua 决定请求形状、地产操作和回包；核心准备版本化地产变更，与扣卡共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1031, name = "购地卡", opcode = 96, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 6, "购地卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    local property = core.call("property.prepare", { operation = "purchase" })
    local state = core.call("game.snapshot")
    assert(state.actors[request.actor + 1].cash > property.price, "购地现金不足")
    core.call("funds.prepare", { actor = request.actor, cash = -property.price })
    -- 回显槽位/背包及有符号目标 WORD，确认后客户端按对应卡牌消费者更新建筑。
    return { protocol.inner(0x40B0, request.game_id, request.payload:sub(5)) }
end
return M
