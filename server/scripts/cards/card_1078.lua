-- 清除卡（资源编号 1078）。本文件是该卡的独立业务入口。
-- C2S 操作号 135；request.payload 是未加密的完整内部报文，包含操作号。
-- C2S135/S2C40D7 为 8 字节，+6 指定仍在场的角色，响应将 +7 保留字节归零。
-- 策划可在此调整需清除的状态；NPC 附身倒计时及同盟矩阵由核心在提交前校验。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local active_target = require("core.active_target")
local M = { id = 1078, name = "清除卡", opcode = 135, reward_enabled = true, implementation = "lua" }
function M.use(request)
    local target = active_target.decode(request)
    core.call("card.prepare", { card = M.id })
    -- 附身还需通过核心解除附身强度；计时炸弹必须同时清除归属者。
    -- 原规则保留状态免疫、攻击/伤害增益，不将“清除”解释成角色完全重置。
    core.call("status.prepare_clear", { target = target, fields = {
        "possession", "timed_bomb", "sleepwalking", "turtle",
        "stay", "one_step", "six_steps", "frozen",
    } })
    core.call("relations.clear_actor", { target = target })
    return { protocol.inner(0x40D7, request.game_id, active_target.response_body(request)) }
end
return M
