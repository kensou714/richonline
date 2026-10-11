-- 经典局最后存活者的胜负分配。奖励策略来自准入层，余额/战绩/投递由C++原子持久化。
-- 本模块不沿用BOSS首通奖励，不将尚未实现的月限比较伪装成平局。
local M = {}
function M.plan(request)
    local winner, actors = -1, core.array()
    for index, value in ipairs(request.active) do
        assert(value == 0 or value == 1, "无效活动标记")
        if value == 1 then
            assert(winner == -1, "尚有多名活动角色")
            winner = index - 1
        end
        actors[index] = {
            slot = index - 1,
            outcome = value == 1 and "win" or "loss",
            rank = value == 1 and request.win_rank or request.loss_rank,
        }
    end
    assert(#actors >= 2 and #actors <= 4 and winner >= 0, "最终结算人数不匹配")
    return {winner = winner, actors = actors}
end
return M
