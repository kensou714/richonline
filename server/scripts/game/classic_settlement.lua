-- 经典局最后存活者的胜负分配。奖励策略来自准入层，余额/战绩/投递由C++原子持久化。
-- 月限按用户确认的总资产规则排名；并列第一各自获胜，不显示整局平局。
local M = {}
function M.plan(request)
    if request.reason == "month_limit" then
        assert(#request.players >= 2 and #request.players <= 4 and #request.rank_images == 4,
            "月限结算人数或排名图片配置不完整")
        local totals, highest, active_count = {}, 0, 0
        for index, player in ipairs(request.players) do
            assert(type(player.active) == "boolean", "活动资格必须来自实际对局")
            local total = 0
            for _, key in ipairs({"cash", "deposit", "stocks", "property"}) do
                local value = player[key]
                assert(math.type(value) == "integer" and value >= 0 and value <= math.maxinteger - total,
                    "资产缺失或累计溢出")
                total = total + value
            end
            totals[index] = total
            if player.active then
                active_count = active_count + 1
                highest = math.max(highest, total)
            end
        end
        assert(active_count >= 2, "月限排名至少需要两名存活者")
        local winners, actors = core.array(), core.array()
        for index, player in ipairs(request.players) do
            local place = 1
            for other, candidate in ipairs(request.players) do
                if candidate.active and (not player.active or totals[other] > totals[index]) then
                    place = place + 1
                end
            end
            local winner = player.active and totals[index] == highest
            assert(math.type(request.rank_images[place]) == "integer", "缺少名次图片索引")
            if winner then winners[#winners + 1] = index - 1 end
            actors[index] = {slot = index - 1, outcome = winner and "win" or "loss",
                rank = request.rank_images[place], place = place, assets = totals[index]}
        end
        return {winners = winners, actors = actors}
    end
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
