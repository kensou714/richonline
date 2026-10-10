-- 四步卡（资源编号 1082）。本文件是该卡的独立业务入口。
-- C2S 操作号 139；request.payload 是未加密的完整内部报文，包含操作号。
-- 请求恰为 6 字节，仅含操作号、日历、主背包槽；它不携带目标角色或可选骰点。
-- 成功确认后必须发送 4011 路线。本次固定走 4 步，沿途交互及落点续接交给核心。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local move = require("core.move_card")
local M = { id = 1082, name = "四步卡", opcode = 139, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 6, "四步卡请求长度错误")
    return move.use(request, M.id, 0x40DB, 4)
end
return M
