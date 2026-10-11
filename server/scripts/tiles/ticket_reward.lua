-- 点券格只确认落点：客户端随后自己排奖励动画及6062，不能再发一笔加点消息。
local protocol = require("core.protocol")
local M = {}
function M.land(request, amount)
    local supported = false
    for _, capability in ipairs(core.capabilities()) do
        if capability == "tile.tickets.prepare" then supported = true end
    end
    -- 旧EXE或无共享账本的入口继续原生处理；必须在准备任何资金事务前回退。
    if not supported or not request.ticket_landing_available then return core.call("tile.native") end
    if request.synthetic_actor or request.controlled then amount = 0 end
    core.call("tile.tickets.prepare", { amount = amount })
    return { protocol.inner(0x4013, request.game_id, string.pack("<i2", request.position)) }
end
return M
