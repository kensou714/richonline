-- 火焰陷阱（资源编号 1183）。本文件是该卡的独立业务入口。
-- C2S 操作号 157；request.payload 是未加密的完整内部报文，包含操作号。
-- 请求为 8 字节：操作号、日历、手牌槽、银行标记、带符号中心格号。
-- Lua 计算方形覆盖区、筛选候选格并构造 40ED；EXE 一次提交全部物件与扣卡。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
-- 火焰只排除三类传送入口；静态格 2/3 可以燃烧，与冰冻陷阱的规则不同。
local forbidden = { [28] = true, [58] = true, [61] = true }
local M = { id = 1183, name = "火焰陷阱", opcode = 157, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 8, "火焰陷阱请求长度错误")
    core.call("card.prepare", { card = M.id })
    assert(core.call("game.snapshot").can_act, "当前角色不能使用陷阱")
    -- 半径与持续回合数来自本房间的服务端资源；伤害及衰减仍由核心落点/回合事务处理。
    local rules = core.call("research.traps", { kind = "fire" })
    assert(rules.fire_radius >= 1 and rules.fire_radius <= 8, "火焰半径无效")
    assert(rules.fire_rounds >= 1 and rules.fire_rounds <= 127, "火焰回合数无效")
    local map = core.call("map.info")
    local position = string.unpack("<i2", request.payload, 7)
    assert(map.width > 0 and map.height > 0 and map.width * map.height <= 32768, "陷阱地图尺寸无效")
    assert(position >= 0 and position < map.width * map.height, "火焰中心越界")
    -- 原协议只要求中心在范围内，覆盖边缘不再次限制范围；中心本身可以是不可放置格。
    assert(core.call("map.cell", { position = position }).ground_visible, "火焰中心不在允许范围")
    local x, y = position % map.width, position // map.width
    local radius = rules.fire_radius
    local objects = core.array()
    for row = math.max(0, y - radius), math.min(map.height - 1, y + radius) do
        for col = math.max(0, x - radius), math.min(map.width - 1, x + radius) do
            local target = row * map.width + col
            local cell = core.call("map.cell", { position = target })
            if cell.walkable and not cell.active_actor_occupied and not cell.ground_occupied
                and not forbidden[cell.static_type] then
                -- NPC 26 记录施放者和剩余回合数，供原有火焰时钟及伤害结算读取。
                objects[#objects + 1] = { position = target, npc = 26, byte7 = request.actor, byte8 = rules.fire_rounds }
            end
        end
    end
    -- 整片区域都被排除时仍按客户端规则消耗卡牌；空数组也提交版本检查，不能提前返回失败。
    core.call("ground.prepare_batch", { objects = objects })
    return { protocol.inner(0x40ED, request.game_id, request.payload:sub(5)) }
end
return M
