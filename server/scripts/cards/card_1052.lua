-- 均贫卡（资源编号 1052）。本文件是该卡的独立业务入口。
-- C2S 操作号 115；request.payload 是未加密的完整内部报文，包含操作号。
-- 金额规则与通信响应在 Lua 中计算；所有角色资金、同盟状态与扣卡由核心共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1052, name = "均贫卡", opcode = 115, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 8, "均贫请求长度错误")
    core.call("card.prepare", { card = M.id })
    local target = request.payload:byte(7)
    local state = core.call("game.snapshot")
    local other, current = state.actors[target + 1], state.actors[request.actor + 1]
    assert(other and other.active and target ~= request.actor, "均贫目标无效")
    local total = current.cash + other.cash
    assert(total <= 0x7FFFFFFF, "现金合计超出客户端有符号 DWORD")
    -- 与客户端算术右移一致：奇数向下取整，存款与点券保持原值。
    local average = total // 2
    core.call("funds.prepare", { actor = target, cash = average - other.cash })
    core.call("funds.prepare", { actor = request.actor, cash = average - current.cash })
    core.call("relations.break", { target = target })
    return { protocol.inner(0x40C3, request.game_id, request.payload:sub(5, 7) .. "\0") }
end
return M
