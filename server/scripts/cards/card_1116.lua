-- 传送卡（资源编号 1116）。本文件是该卡的独立业务入口。
-- C2S 操作号 143；request.payload 是未加密的完整内部报文，包含操作号。
-- C2S143/S2C40DF 为 8 字节：+6 是带符号目标格号；目标必须是无地面物及角色/宠物占格的道路。
-- 传送只更改施放者的权威坐标并播放客户端动画，不在此处伪造落点回包。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1116, name = "传送卡", opcode = 143, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 8, "传送卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    local position = string.unpack("<i2", request.payload, 7)
    assert(position >= 0, "传送目标不是道路")
    local cell = core.call("map.cell", { position = position })
    assert(cell.walkable and not cell.ground_occupied and not cell.placement_occupied, "传送目标不可用或已占用")
    -- 核心会按原始收容状态再核验占格，并在共同提交前检查地面版本与角色快照。
    core.call("actor.prepare_positions", { positions = { { actor = request.actor, position = position } } })
    return { protocol.inner(0x40DF, request.game_id, request.payload:sub(5)) }
end
return M
