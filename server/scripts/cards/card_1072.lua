-- 察看卡（资源编号 1072）。本文件是该卡的独立业务入口。
-- C2S 操作号 132；request.payload 是未加密的完整内部报文，包含操作号。
-- 察看卡只触发客户端本地检查窗，不改变目标的资金、手牌或状态。
-- C2S132 的目标在 +6；S2C40D4 的 +7 保留字节必须归零，没有后续 C2S 确认。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local active_target = require("core.active_target")
local M = { id = 1072, name = "察看卡", opcode = 132, reward_enabled = true, implementation = "lua" }
function M.use(request)
    active_target.decode(request)
    core.call("card.prepare", { card = M.id })
    return { protocol.inner(0x40D4, request.game_id, active_target.response_body(request)) }
end
return M
