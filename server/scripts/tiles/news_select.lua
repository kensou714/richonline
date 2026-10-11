-- 新闻事件由核心按颜色、资源、资金/库存/状态可闭合性先准备候选。
-- 此处只处理已准备候选的相对权重；核心复核抽样序号后才提交三种权威状态。
local M = {}
function M.select(request, static_type)
    assert(request.type == static_type, "新闻格类型不一致")
    local total = 0
    for _, option in ipairs(request.options) do
        assert(math.type(option.event) == "integer", "新闻事件编号无效")
        assert(math.type(option.weight) == "integer" and option.weight > 0, "新闻权重无效")
        total = total + option.weight
    end
    assert(total > 0 and total <= 2147483647, "新闻候选奖池无效")
    local draw = request.draw
    assert(math.type(draw) == "integer" and draw >= 0 and draw < total, "新闻抽样越界")
    for index, option in ipairs(request.options) do
        if draw < option.weight then return index - 1 end
        draw = draw - option.weight
    end
    error("新闻权重选择失败")
end
return M
