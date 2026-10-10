-- 查税卡（资源编号 1051）。本文件是该卡的独立业务入口。
-- C2S 操作号 114；request.payload 是未加密的完整内部报文，包含操作号。
-- 金额规则与通信响应在 Lua 中计算；所有角色资金、同盟状态与扣卡由核心共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1051, name = "查税卡", opcode = 114, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 8, "查税请求长度错误")
    core.call("card.prepare", { card = M.id })
    local target = request.payload:byte(7)
    local state = core.call("game.snapshot")
    local payer, receiver = state.actors[target + 1], state.actors[request.actor + 1]
    assert(payer and payer.active and target ~= request.actor, "查税目标无效")
    assert(payer.deposit ~= core.null and receiver.deposit ~= core.null, "存款状态未知")
    -- 客户端分别对现金、存款取十分之一并向下取整，不能对合计金额只算一次。
    local cash, deposit = payer.cash // 10, payer.deposit // 10
    core.call("funds.prepare", { actor = target, cash = -cash, deposit = -deposit })
    core.call("funds.prepare", { actor = request.actor, cash = cash, deposit = deposit })
    core.call("relations.break", { target = target })
    return { protocol.inner(0x40C2, request.game_id, request.payload:sub(5, 7) .. "\0") }
end
return M
