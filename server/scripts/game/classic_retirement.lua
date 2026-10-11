-- 经典局破产后的活动名单和轮序。地产/资金事务由C++准备并一次提交。
-- 淘汰保留原槽号；普通模式不套用BOSS一对一胜负政策。
local M = {}
function M.plan(request)
    local active = {}
    for index, value in ipairs(request.active) do active[index] = value end
    assert(active[request.bankrupt + 1] == 1, "不能重复淘汰角色")
    active[request.bankrupt + 1] = 0
    local count = 0
    for _, value in ipairs(active) do count = count + value end
    -- 单独存活时由C++的全员持久结算接管，不进入下一4010。
    assert(count >= 1, "不能淘汰全部角色")
    local function next_active(slot)
        repeat slot = (slot + 1) % #active until active[slot + 1] == 1
        return slot
    end
    local anchor = request.anchor
    if anchor == request.bankrupt then anchor = next_active(anchor) end
    return {active = active, anchor = anchor, next = next_active(request.actor)}
end
return M
