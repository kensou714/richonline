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
    -- 6799C0：经典模式均分存款；现有BOSS模式均分现金。旧核心快照没有mode，沿用BOSS。
    local account = state.mode == 0 and "deposit" or "cash"
    local total, count = 0, 0
    for _, actor in ipairs(state.actors) do
        if actor.active then
            assert(math.type(actor[account]) == "integer", "均富账户余额未知")
            total, count = total + actor[account], count + 1
        end
    end
    assert(count > 0 and total <= 0x7FFFFFFF, "均富账户合计超出客户端范围")
    -- 客户端给每位仍在局内的角色所选账户至少1元，不修改另一账户或点券。
    local average = math.max(1, total // count)
    for _, actor in ipairs(state.actors) do
        if actor.active then core.call("funds.prepare", { actor = actor.slot, [account] = average - actor[account] }) end
    end
    return { protocol.inner(0x40F6, request.game_id, request.payload:sub(5)) }
end
return M
