-- 局内股票买卖策略。数量/价格/持仓来自核心，金额由核心按客户端float乘法取整。
-- 无数据库或移动状态能力：成交不推进回合，失败也不能发送会推进6080的4206。
local protocol = require("core.protocol")
local M = {}
function M.open(request)
    -- 4200同步大盘，随后每个槽一份4201；重复历史包会追加历史，不能拿作心跳。
    local messages = {protocol.inner(0x4200, request.game_id,
        string.pack("<fff", request.previous_index, request.current_index, request.factor))}
    for _, row in ipairs(request.history) do
        assert(#row.prices == 30, "股票历史必须有30点")
        local body = string.pack("<i2I2", row.slot, 0)
        for _, price in ipairs(row.prices) do body = body .. string.pack("<f", price) end
        messages[#messages + 1] = protocol.inner(0x4201, request.game_id, body)
    end
    return messages
end
function M.quote(request)
    return protocol.inner(0x4203, request.game_id, string.pack("<i2I2f", request.slot, 0, request.price))
end
function M.market(request)
    assert(#request.prices >= 1 and #request.prices <= 10, "股票行情槽数必须为1至10")
    local body = string.pack("<ff", request.current_index, request.factor)
    -- 客户端固定读取+52的提示标志，不随本局股票数量移动。
    for slot = 1, 10 do body = body .. string.pack("<f", request.prices[slot] or 0) end
    return protocol.inner(0x4202, request.game_id, body .. string.pack("<I1", request.notify and 1 or 0))
end
function M.trade(request)
    local reason, deposit = "accepted", request.deposit
    local buy, quantity = request.buy, request.quantity
    if request.restricted then reason = "restricted"
    elseif buy and request.change >= request.rise_limit then reason = "rise_limit"
    elseif not buy and request.change <= request.fall_limit then reason = "fall_limit"
    elseif not request.amount_valid then reason = "amount_limit"
    elseif buy and request.supply < quantity then reason = "insufficient_supply"
    elseif not buy and request.holding < quantity then reason = "insufficient_holding"
    elseif buy and deposit < request.amount then reason = "insufficient_deposit"
    elseif not buy and request.amount > 2147483647 - deposit then reason = "deposit_limit"
    elseif buy and quantity > 2147483647 - request.holding then reason = "holding_limit"
    elseif not buy and quantity > 2147483647 - request.supply then reason = "supply_limit" end
    local accepted, message = reason == "accepted", ""
    if accepted then
        deposit = deposit + (buy and -request.amount or request.amount)
        -- 20字节成交包：+10保留WORD，+12原始float价，+16最终存款（不是增量）。
        message = protocol.inner(buy and 0x4204 or 0x4205, request.game_id,
            string.pack("<i2i2i2I2fi4", request.actor, request.slot, quantity, 0, request.price, deposit))
    end
    return {accepted = accepted, reason = reason, deposit = deposit, message = message}
end
return M
