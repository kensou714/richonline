-- 冰冻陷阱（资源编号 1181）。本文件是该卡的独立业务入口。
-- C2S 操作号 155；request.payload 是未加密的完整内部报文，包含操作号。
-- 请求为 8 字节：操作号、日历、手牌槽、银行标记、带符号目标格号。
-- Lua 负责目标筛选和 40EB 回包；EXE 只准备并共同提交地面、库存状态。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local ground = require("core.ground")
local forbidden = { [2] = true, [3] = true, [28] = true, [58] = true, [61] = true }
local M = { id = 1181, name = "冰冻陷阱", opcode = 155, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 8, "冰冻陷阱请求长度错误")
    core.call("card.prepare", { card = M.id })
    assert(core.call("game.snapshot").can_act, "当前角色不能使用陷阱")
    -- 确认本房间已装载冰冻落点规则；时长来自服务端资源副本，不能凭空开放效果。
    local rules = core.call("research.traps", { kind = "ice" })
    assert(rules.freeze_timer >= 1 and rules.freeze_timer <= 127, "冰冻时长无效")
    local map = core.call("map.info")
    local position = string.unpack("<i2", request.payload, 7)
    assert(map.width > 0 and map.height > 0 and map.width * map.height <= 32768, "陷阱地图尺寸无效")
    assert(position >= 0 and position < map.width * map.height, "冰冻目标越界")
    local cell = core.call("map.cell", { position = position })
    assert(cell.ground_visible, "冰冻目标不在允许范围")
    -- 核心统一角色、宠物以及离场状态的放置占格。
    assert(cell.walkable and not ground.occupied(cell) and not cell.ground_occupied
        and not forbidden[cell.static_type], "冰冻目标不能放置陷阱")
    -- NPC 25 的两个元数据字节固定为 255；踩中后的免疫、冻结和移除沿用核心落点事务。
    core.call("ground.prepare", { position = position, npc = 25, byte7 = 255, byte8 = 255 })
    return { protocol.inner(0x40EB, request.game_id, request.payload:sub(5)) }
end
return M
