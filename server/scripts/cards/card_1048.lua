-- 送神卡（资源编号 1048）。本文件是该卡的独立业务入口。
-- C2S 操作号 113；request.payload 是未加密的完整内部报文，包含操作号。
-- Lua校验目标和附身，核心准备附身状态/时钟清理，成功后恢复掷骰操作。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local active_target = require("core.active_target")
local M = { id = 1048, name = "送神卡", opcode = 113, reward_enabled = true, implementation = "lua" }
function M.use(request)
    -- 旧安装版缺少此细粒度接口时，继续使用原生送神事务，不先准备扣卡。
    local can_detach = false
    for _, name in ipairs(core.capabilities()) do
        if name == "npc.prepare_detach" then can_detach = true end
    end
    if not can_detach then return core.call("game.native") end

    local target = active_target.decode(request)
    core.call("card.prepare", { card = M.id })
    local person = core.call("actor.relocation_snapshot")[target + 1]
    assert(person and person.active and person.raw_available, "送神目标暂不可用")
    local status = core.call("game.snapshot").actors[target + 1]
    assert(type(status.possession) == "number", "目标没有附身神明")
    -- NPC正等待转盘或结算时核心拒绝；只解除附身及其强度，不清其他持续状态。
    core.call("npc.prepare_detach", { target = target })
    -- 40C1只有7字节；请求+7为未使用字节，不能照抄进成功回包。
    return { protocol.inner(0x40C1, request.game_id, request.payload:sub(5, 7)) }
end
return M
