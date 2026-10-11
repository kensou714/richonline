-- 毒气卡（资源编号 1182）。本文件是该卡的独立业务入口。
-- C2S 操作号 156；request.payload 是未加密的完整内部报文，包含操作号。
-- Lua计算十字覆盖与衰减层，核心按格顺序投影资金重算伤害并统一提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1182, name = "毒气卡", opcode = 156, reward_enabled = true, implementation = "lua" }
function M.use(request)
    local can_prepare = false
    for _, name in ipairs(core.capabilities()) do
        if name == "combat.prepare_poison" then can_prepare = true end
    end
    if not can_prepare then return core.call("game.native") end
    assert(#request.payload == 8 and request.payload:byte(7) == 1, "毒气卡请求字段错误")
    core.call("card.prepare", { card = M.id })
    local snapshot = core.call("game.snapshot")
    assert(snapshot.can_act, "当前角色不能使用毒气卡")
    local origin = snapshot.actors[request.actor + 1].position
    local map = core.call("map.info")
    local range = core.call("research.poison_rules").range
    assert(range >= 1 and range <= 4, "毒气范围无效")
    local x, y = origin % map.width, origin // map.width
    local footprint = { { position = origin, layer = 0 } }
    -- 639170先中心，再逐层按下、左、上、右处理；相邻第一格同样属于衰减层0。
    local directions = { { 0, 1 }, { -1, 0 }, { 0, -1 }, { 1, 0 } }
    for distance = 1, range do
        for _, direction in ipairs(directions) do
            local col, row = x + direction[1] * distance, y + direction[2] * distance
            if col >= 0 and col < map.width and row >= 0 and row < map.height then
                local position = row * map.width + col
                -- 射线穿过非道路，但非道路格不作为命中格；不能遇到建筑就停止延伸。
                if core.call("map.cell", { position = position }).walkable then
                    footprint[#footprint + 1] = { position = position, layer = distance - 1 }
                end
            end
        end
    end
    core.call("combat.prepare_poison", { footprint = footprint })
    -- 40EC沿用现有字段回显；+7仅为不透明尾字节，不能把它解释成格号。
    return { protocol.inner(0x40EC, request.game_id, request.payload:sub(5)) }
end
return M
