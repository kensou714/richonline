-- 开店卡（资源编号 1034）。本文件是该卡的独立业务入口。
-- C2S 操作号 99；request.payload 是未加密的完整内部报文，包含操作号。
-- 经典模式选择已归属的非零级小型地产，改为1级商店；不转移产权、不扣现金。
-- BOSS宿主只有大型地产，保留原生拒绝入口；不把这张卡加入BOSS随机奖励池。
local protocol = require("core.protocol")
local M = { id = 1034, name = "开店卡", opcode = 99, reward_enabled = false, implementation = "lua_classic" }
function M.use(request)
    if request.mode ~= 0 then return core.call("game.native") end
    assert(#request.payload == 8, "开店卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    local target = string.unpack("<i2", request.payload, 7)
    core.call("property.prepare", { operation = "open_shop", property = target })
    -- 40B3本身排队转换、扣卡和恢复操作，不再发送第二份地产或扣卡消息。
    return { protocol.inner(0x40B3, request.game_id, request.payload:sub(5)) }
end
return M
