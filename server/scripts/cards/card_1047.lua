-- 请神卡（资源编号 1047）。本文件是该卡的独立业务入口。
-- C2S 操作号 112；request.payload 是未加密的完整内部报文，包含操作号。
-- Lua选择距离目标最近的可召地面神；核心准备完整附身、奖励、地面补充与等待事务。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local active_target = require("core.active_target")
local M = { id = 1047, name = "请神卡", opcode = 112, reward_enabled = true, implementation = "lua" }
function M.use(request)
    local can_prepare = false
    for _, name in ipairs(core.capabilities()) do
        if name == "npc.prepare_summon" then can_prepare = true end
    end
    if not can_prepare then return core.call("game.native") end
    local target = active_target.decode(request)
    local card = core.call("card.prepare", { card = M.id })
    local candidates = core.call("npc.summon_candidates", { target = target })
    local chosen
    for _, candidate in ipairs(candidates) do
        if not chosen or candidate.distance_squared < chosen.distance_squared or
            (candidate.distance_squared == chosen.distance_squared and candidate.position < chosen.position) then
            chosen = candidate
        end
    end
    assert(chosen, "目标附近没有可召神明")
    local effects = core.call("npc.prepare_summon", { position = chosen.position })
    -- 40C0为九字节：槽位、银行、地面位置WORD、目标角色；请求+7不是响应字段。
    local packets = { protocol.inner(0x40C0, request.game_id, string.pack("<BBi2B", card.slot, card.bank, chosen.position, target)) }
    -- 保留福神奖励、衰神丢卡及地面补充的准确顺序；自己召钱神时由核心等待34。
    for _, packet in ipairs(effects) do packets[#packets + 1] = packet end
    return packets
end
return M
