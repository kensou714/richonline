-- 遥控骰子（资源编号 1038）。本文件是该卡的独立业务入口。
-- C2S 操作号 103；request.payload 是未加密的完整内部报文，包含操作号。
-- 12 字节请求：+4 槽位、+5 主背包、+6 骰点、+7 保留字节、+8 四字节扩展。
-- 骰点必须为 1–6，构造器扩展必须为 0；保留字节沿用原生语义，不解释为目标。
-- 本次所选骰点覆盖持续一步/六步/乌龟的步数，不清除或延长这些状态。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local move = require("core.move_card")
local M = { id = 1038, name = "遥控骰子", opcode = 103, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 12, "遥控骰子请求长度错误")
    local steps = request.payload:byte(7)
    assert(steps >= 1 and steps <= 6, "遥控骰子点数超出范围")
    assert(string.unpack("<I4", request.payload, 9) == 0, "遥控骰子扩展字段未支持")
    return move.use(request, M.id, 0x40B7, steps)
end
return M
