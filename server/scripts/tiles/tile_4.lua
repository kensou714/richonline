-- 彩票格：一个未售号码1000现金，全部进入与新闻罚款共用的奖池。
-- 0029的-2自动选择在客户端解析，服务器不把负数写入号码表。
local M = {}
function M.purchase(request)
    local number = request.requested
    if request.timed_out or number < 1 or not request.available or request.cash <= 1000 then number = -1 end
    assert(number == -1 or (math.type(number) == "integer" and number <= 32), "彩票号码无效")
    return { number=number, fee=number == -1 and 0 or 1000,
        message=string.pack("<I2I2b", 0x402B, request.game_id, number) }
end
function M.draw(request)
    local number = request.number
    assert(math.type(number) == "integer" and number >= 1 and number <= 32, "开奖号码无效")
    local winner = request.owners[number]
    -- 没人中奖保留号码和奖池；中奖才清全部号码、把奖池恢复到5000。
    return {number=number, winner=winner, prize=request.jackpot,
        next_jackpot=winner == -1 and request.jackpot or 5000, reset=winner ~= -1}
end
return M
