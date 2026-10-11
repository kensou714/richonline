-- 每月1日轮首的存款利息。日期门和活动名单由C++提供，医院/监狱/绑架不影响资格。
-- 只返回意图；C++复核金额和版本后共同提交，不能再次通知客户端加钱。
local M = {}
function M.plan(request)
    local effects = core.array()
    for _, actor in ipairs(request.actors) do
        assert(math.type(actor.actor) == "integer" and actor.actor >= 0 and actor.actor < 4,
            "利息角色槽无效")
        assert(math.type(actor.deposit) == "integer" and actor.deposit >= 0 and actor.deposit <= 0x7FFFFFFF,
            "利息存款无效")
        local interest = actor.deposit // 10
        local after = actor.deposit + interest
        assert(after <= 0x7FFFFFFF, "利息存款溢出")
        effects[#effects + 1] = { actor=actor.actor, interest=interest, after_deposit=after }
    end
    return { effects=effects }
end
return M
