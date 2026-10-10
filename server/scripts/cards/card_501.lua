-- 引爆卡（资源编号 501）。本文件是该卡的独立业务入口。
-- C2S 操作号 159；request.payload 是未加密的完整内部报文，包含操作号。
-- Lua编排确认与连锁回包；核心在完整回包校验后统一提交库存、伤害和地面变更。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 501, name = "引爆卡", opcode = 159, reward_enabled = true, implementation = "lua" }
function M.use(request)
    local can_prepare = false
    for _, name in ipairs(core.capabilities()) do
        if name == "combat.prepare_detonation" then can_prepare = true end
    end
    if not can_prepare then return core.call("game.native") end
    assert(#request.payload == 8, "引爆卡请求长度错误")
    local card = core.call("card.prepare", { card = M.id })
    -- 请求+6/+7未初始化；既不解析目标，也不把这两个字节回显到40EF。
    local effects = core.call("combat.prepare_detonation")
    local packets = { protocol.inner(0x40EF, request.game_id, string.pack("BBBB", card.slot, 0, 0, 0)) }
    for _, packet in ipairs(effects) do packets[#packets + 1] = packet end
    -- 核心在破产计划中已排除400B；无可见地雷则准备失败，保留手牌并恢复操作。
    return packets
end
return M
