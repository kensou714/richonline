-- 财神卡（资源编号 1069）。本文件是该卡的独立业务入口。
-- C2S 操作号 130；request.payload 是未加密的完整内部报文，包含操作号。
-- Lua编排财神附身确认；核心统一提交扣卡、附身时钟及后续34转盘等待。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1069, name = "财神卡", opcode = 130, reward_enabled = true, implementation = "lua" }
function M.use(request)
    local can_attach = false
    for _, name in ipairs(core.capabilities()) do
        if name == "npc.prepare_attach" then can_attach = true end
    end
    if not can_attach then return core.call("game.native") end
    assert(#request.payload == 6, "财神卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    core.call("npc.prepare_attach", { npc = 0 })
    -- 不在此发余额或伪造转盘请求；40D2后等客户端34，超时沿用核心转盘策略。
    return { protocol.inner(0x40D2, request.game_id, request.payload:sub(5, 6)) }
end
return M
