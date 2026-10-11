-- Prop.kpd 的十二档金豆券说明；请求不能指定奖励金额或收款账号。
local M = {}
local gold = {
    [100] = 1000, [101] = 5000, [102] = 10000, [103] = 50000, [104] = 100000,
    [113] = 10, [114] = 20, [115] = 30, [116] = 200, [117] = 5,
    [3001] = 500, [3002] = 2000,
}
function M.plan(request)
    local amount = gold[request.product]
    if not amount then return { allowed = false, reason = "mall_consumable_effect_unimplemented" } end
    return { allowed = true, gold = amount }
end
return M
