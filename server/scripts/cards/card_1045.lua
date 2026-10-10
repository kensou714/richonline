-- 定时炸弹（资源编号 1045）。本文件是该卡的独立业务入口。
-- C2S 操作号 110；request.payload 是未加密的完整内部报文，包含操作号。
-- Lua核对请求和目标、构造40BE；核心准备并共同提交手牌与炸弹计时/归属。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1045, name = "定时炸弹", opcode = 110, reward_enabled = true, implementation = "lua" }
function M.use(request)
    local can_prepare = false
    for _, name in ipairs(core.capabilities()) do
        if name == "combat.prepare_timed_bomb" then can_prepare = true end
    end
    if not can_prepare then return core.call("game.native") end
    assert(#request.payload == 8, "定时炸弹请求长度错误")
    local target = request.payload:byte(7)
    assert(target < 8, "定时炸弹目标错误")
    core.call("card.prepare", { card = M.id })
    -- 原始住院/旅馆/绑架状态以及已有炸弹由核心复核，不能用可操作状态代替目标资格。
    local prepared = core.call("combat.prepare_timed_bomb", { target = target })
    return { protocol.inner(0x40BE, request.game_id,
        request.payload:sub(5, 7) .. string.char(prepared.response_opaque7)) }
end
return M
