-- 开路卡（资源编号 1061）。本文件是该卡的独立业务入口。
-- C2S 操作号 122；request.payload 是未加密的完整内部报文，包含操作号。
-- 开路只清除前方十步目的格上的动态物件，不移动施放者、不清除起点。
-- 核心负责真实道路与方向规划；Lua 按路径选择清理格，并编码 40CA 的三字节方向位域。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1061, name = "开路卡", opcode = 122, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 6, "开路卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    local route = core.call("route.preview_open_road")
    assert(#route.directions <= 12, "开路卡方向数量超出回包容量")
    local occupied = {}
    for _, object in ipairs(core.call("ground.snapshot")) do
        occupied[object.position] = true
    end
    local positions = core.array()
    for _, position in ipairs(route.landings) do
        if occupied[position] then
            positions[#positions + 1] = position
            occupied[position] = nil -- 路径可能重复经过同一格，事务只移除一次。
        end
    end
    core.call("ground.prepare_remove", { positions = positions })
    local packed = { 0, 0, 0 }
    for index, direction in ipairs(route.directions) do
        assert(direction >= 0 and direction <= 3, "开路卡方向无效")
        local byte = (index - 1) // 4 + 1
        packed[byte] = packed[byte] | (direction << (((index - 1) % 4) * 2))
    end
    -- 6 字节通用头和槽位，后接 3 字节方向；未使用的方向位保持 0。
    local body = request.payload:sub(5) .. string.char(packed[1], packed[2], packed[3])
    return { protocol.inner(0x40CA, request.game_id, body) }
end
return M
