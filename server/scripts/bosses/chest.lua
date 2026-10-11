-- BossWar 第三个字段是权重，不是百分比；原始奖池总和可能大于100。
local M = {}
-- 核心已排除玩家脚下、孤立格和不连通区域。这里只编排均匀抽选，
-- 不创建地面对象；核心复核返回位置后才提交420C及宝箱阶段状态。
function M.spawn(request)
    local positions = request.positions
    assert(type(positions) == "table" and #positions > 0, "宝箱道路候选为空")
    local draw = core.call("boss.chest_position_random", {bound = #positions})
    assert(math.type(draw) == "integer" and draw >= 0 and draw < #positions, "宝箱位置随机数越界")
    local position = positions[draw + 1]
    assert(math.type(position) == "integer" and position >= 0 and position <= 32767, "宝箱位置无效")
    return position
end
function M.select(request)
    local total = 0
    for _, entry in ipairs(request.drops) do
        assert(math.type(entry.weight) == "integer" and entry.weight > 0, "宝箱权重无效")
        total = total + entry.weight
    end
    assert(total > 0 and total <= 2147483647, "宝箱奖池无效")
    local draw = core.call("boss.chest_random", {bound = total})
    assert(math.type(draw) == "integer" and draw >= 0 and draw < total, "宝箱随机数越界")
    for index, entry in ipairs(request.drops) do
        if draw < entry.weight then return index - 1 end
        draw = draw - entry.weight
    end
    error("宝箱奖池选择失败")
end
return M
