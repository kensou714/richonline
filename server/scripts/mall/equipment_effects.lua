-- 已装备物品的回合效果。资源解析、条件求值和账本提交由 C++ 核心提供。
-- NEW7D6BE0/7D6C10：固定回血 + 当前现金 * healR / 1000；healR 是千分比。
local M = {}
function M.healing(request)
    assert(math.type(request.cash) == "integer" and request.cash >= 0, "equipment_cash_invalid")
    assert(math.type(request.flat) == "integer" and request.flat >= 0, "equipment_heal_flat_invalid")
    assert(math.type(request.per_mille) == "integer" and request.per_mille >= 0, "equipment_heal_rate_invalid")
    -- 客户端先取32位乘积，再有符号除法。当前资源的比例均带低现金条件。
    -- 超出非负权威资金域的资源组合交由核心拒绝，不能取绝对值伪造回血。
    local product = (request.cash * request.per_mille) & 0xffffffff
    if product >= 0x80000000 then product = product - 0x100000000 end
    local scaled = product < 0 and -((-product) // 1000) or product // 1000
    return request.flat + scaled
end
return M
