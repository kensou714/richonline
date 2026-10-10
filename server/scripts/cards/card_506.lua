-- 冬眠卡（资源编号 506）。本文件是该卡的独立业务入口。
-- C2S 操作号 164；request.payload 是未加密的完整内部报文，包含操作号。
-- Lua选择全部可参与角色；核心在同一事务解析免疫/梦游保护卡、冻结、同盟和扣卡。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 506, name = "冬眠卡", opcode = 164, reward_enabled = true, implementation = "lua" }
function M.use(request)
    local can_prepare = false
    for _, name in ipairs(core.capabilities()) do
        if name == "hibernate.prepare" then can_prepare = true end
    end
    -- 源码脚本与安装EXE共用目录；旧EXE在任何准备动作之前回到既有冬眠事务。
    if not can_prepare then return core.call("game.native") end
    assert(#request.payload == 6, "冬眠卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    local snapshot = core.call("hibernate.snapshot")
    local targets = core.array()
    local source_eligible = false
    for _, target in ipairs(snapshot.actors) do
        local eligible = target.present and target.hotel == -1 and target.hospital == -1
            and target.jail == -1 and target.kidnapped == -1 and target.frozen == 0
        if eligible then
            if target.slot == snapshot.actor then source_eligible = true
            else targets[#targets + 1] = target.slot end
        end
    end
    assert(source_eligible and #targets > 0, "冬眠卡需要施放者和至少一名可参与角色")
    -- 免疫或持有保护卡的目标仍属于参与者，先解除双方同盟，再由核心处理抵挡。
    core.call("hibernate.prepare", { targets = targets, frozen_turns = snapshot.frozen_turns })
    return { protocol.inner(0x40F4, request.game_id, request.payload:sub(5, 6)) }
end
return M
