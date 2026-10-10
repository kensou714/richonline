-- 同盟卡（资源编号 1060）。本文件是该卡的独立业务入口。
-- C2S 操作号 121；request.payload 是未加密的完整内部报文，包含操作号。
-- C2S121 为 8 字节；目标角色在 +6，+7 保留字节在 40C9 响应中归零。
-- 同盟双方的关系计数在同一核心事务内写入，后续回合衰减仍由核心时钟负责。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local active_target = require("core.active_target")
local M = { id = 1060, name = "同盟卡", opcode = 121, reward_enabled = true, implementation = "lua" }
function M.use(request)
    local target = active_target.decode(request)
    core.call("card.prepare", { card = M.id })
    assert(target ~= request.actor, "不能与自己结盟")
    local days = core.call("relations.rules").alliance_days
    assert(days >= 1 and days <= 127, "同盟天数无效")
    core.call("relations.prepare", { target = target, days = days })
    return { protocol.inner(0x40C9, request.game_id, active_target.response_body(request)) }
end
return M
