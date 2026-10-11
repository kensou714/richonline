-- BossWar 第三个字段是权重，不是百分比；原始奖池总和可能大于100。
local M = {}
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
