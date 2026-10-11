-- 57类兑换格：NEW7C54B0在4013后本地处理25点券换2000现金。
-- 只确认落点，不再发资金增量；合成BOSS不扣点券，受控或脚本阶段跳过。
local protocol = require("core.protocol")
local M = { type = 57, implementation = "lua" }
function M.land(request)
    local supported = false
    for _, capability in ipairs(core.capabilities()) do
        if capability == "tile.merchant.prepare" then supported = true end
    end
    -- 旧核心或未配置兑换会话时在准备事务前回退，不混用两种提交路径。
    if not supported or not request.merchant_landing_available then return core.call("tile.native") end
    local state = core.call("tile.merchant.prepare")
    local credit, cost = 0, 0
    if not state.scripted and not request.controlled then
        if request.synthetic_actor then
            credit = 2000
        elseif state.tickets >= 25 then
            credit, cost = 2000, 25
        end
    end
    return {
        cash_credit = credit, ticket_cost = cost,
        messages = {protocol.inner(0x4013, request.game_id, string.pack("<i2", request.position))},
    }
end
return M
