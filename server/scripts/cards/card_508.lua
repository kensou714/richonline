-- 均富卡（资源编号 508）。本文件是该卡的独立业务入口。
-- C2S 操作号 166；request.payload 是未加密的完整内部报文，包含操作号。
-- 金额规则与通信响应在 Lua 中计算；所有角色资金、同盟状态与扣卡由核心共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 508, name = "均富卡", opcode = 166, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 6, "均富请求长度错误")
    core.call("card.prepare", { card = M.id })
    local state = core.call("game.snapshot")
    local total, count = 0, 0
    for _, actor in ipairs(state.actors) do
        if actor.active then total, count = total + actor.cash, count + 1 end
    end
    assert(count > 0 and total <= 0x7FFFFFFF, "现金合计超出客户端范围")
    -- 客户端给每位仍在局内的角色至少 1 元，仅平均现金，不动存款/点券。
    local average = math.max(1, total // count)
    for _, actor in ipairs(state.actors) do
        if actor.active then core.call("funds.prepare", { actor = actor.slot, cash = average - actor.cash }) end
    end
    return { protocol.inner(0x40F6, request.game_id, request.payload:sub(5)) }
end
return M
