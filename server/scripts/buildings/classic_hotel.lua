-- 饭店kind4：转盘结果是收费倍率，不是住店天数；原服概率尚未恢复。
local M = {}
local function signed32(value)
    value = value & 0xFFFFFFFF
    return value >= 0x80000000 and value - 0x100000000 or value
end
function M.plan(request)
    local result = request.result
    assert(result == -1 or (result >= 1 and result <= 6), "饭店结果无效")
    local amount = signed32(signed32(signed32(request.scale * request.level) * 600) * result)
    if request.price_rise_days > 0 then amount = signed32(amount * 2) end
    return {quote = result == -1 and 0 or amount, message = string.pack("<I2I2b", 0x4028, request.game_id, result)}
end
function M.visit(request)
    local road, width, inside, heading = request.road, request.width, request.property, -1
    local candidate = inside - 2 * width
    if road == candidate or road == candidate - 1 then heading, inside = 0, road + width end
    candidate = inside + width
    if (heading == -1 and road == candidate) or road == candidate - 1 then heading, inside = 2, road - width end
    candidate = inside + 1
    if (heading == -1 and road == candidate) or road == candidate - width then heading, inside = 1, road - 1 end
    candidate = inside - 2
    if (heading == -1 and road == candidate) or road == candidate - width then heading, inside = 3, road + 1 end
    return {inside = inside, heading = heading}
end
return M
