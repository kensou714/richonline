-- 陷害卡（资源编号 1054）。本文件是该卡的独立业务入口。
-- C2S 操作号 117；request.payload 是未加密的完整内部报文，包含操作号。
-- Lua筛选目标和免疫分支；核心将扣卡、入狱坐标/原始计时及同盟解除共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local active_target = require("core.active_target")
local M = { id = 1054, name = "陷害卡", opcode = 117, reward_enabled = true, implementation = "lua" }
function M.use(request)
    -- 已安装旧EXE与源码共享脚本目录；缺少准备能力时保留原有原生事务。
    local can_prepare = false
    for _, name in ipairs(core.capabilities()) do
        if name == "actor.prepare_jail" then can_prepare = true end
    end
    if not can_prepare then return core.call("game.native") end

    local target = active_target.decode(request)
    assert(target ~= request.actor, "陷害卡不能对自己使用")
    core.call("card.prepare", { card = M.id })
    local person = core.call("actor.relocation_snapshot")[target + 1]
    local jail = core.call("actor.jail_rules")
    assert(person and person.active and person.raw_available and not person.frozen, "陷害目标暂不可用")
    assert(jail.available, "当前地图没有监狱")
    -- 免疫仍扣卡并解除正值同盟，只是不搬移角色、不改停留状态或监狱倒计时。
    core.call("actor.prepare_jail", { target = target, apply = not person.protected_from_status })
    core.call("relations.break", { target = target })
    -- +7是保留字节，不作为刑期；刑期继续来自服务端资源GValue10。
    return { protocol.inner(0x40C5, request.game_id, active_target.response_body(request)) }
end
return M
