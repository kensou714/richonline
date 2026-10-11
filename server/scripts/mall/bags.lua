-- 用户确认采用三颗公平六面骰。随机数由C++核心产生，Lua只规划奖盘槽位和单件奖励。
-- AwardLB第二字段未证实，不把它当权重或数量；每次消耗一个宝袋并发一个奖品实例。
local M = {}
function M.award(request)
    assert(request.bag >= 105 and request.bag <= 107, "宝袋类型无效")
    assert(#request.dice == 3, "宝袋骰子数量无效")
    local sum = 0
    for _, face in ipairs(request.dice) do
        assert(math.type(face) == "integer" and face >= 1 and face <= 6, "宝袋骰点无效")
        sum = sum + face
    end
    assert(#request.products == 16, "宝袋奖盘不完整")
    local product = request.products[sum - 2]
    assert(product == (request.owned_key & 0xFFF), "宝袋奖品键不匹配")
    return {slot=sum, quantity=1, product=product, owned_key=request.owned_key}
end
return M
