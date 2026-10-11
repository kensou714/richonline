-- 经典地产的已授权选择。落点资格、身份、日历和资金提交由C++核心统一持有。
local M = {}
function M.choose(request)
    assert(request.choice == 0x20 or request.choice == 0x21, "经典地产选择类型无效")
    local accepted, outcome = false, "declined"
    if request.timed_out then
        outcome = "timed_out"
    elseif request.requested then
        if request.cash <= request.cost then
            outcome = "insufficient_funds"
        else
            accepted, outcome = true, "accepted"
        end
    end
    local owner, level = request.owner, request.level
    -- 状态2确认后仍花费现金，但产权和等级保持原状。
    if accepted and request.possession ~= 2 then
        if request.choice == 0x20 then owner = request.actor else level = level + 1 end
    end
    return {
        accepted = accepted, charged = accepted and request.cost or 0, outcome = outcome,
        owner = owner, level = level,
        message = string.pack("<I2I2B", request.choice + 0x4000, request.game_id, accepted and 1 or 0),
    }
end
return M
