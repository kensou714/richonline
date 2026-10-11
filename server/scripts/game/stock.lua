-- 局内股票买卖策略。数量/价格/持仓来自核心，金额由核心按客户端float乘法取整。
-- 无数据库或移动状态能力：成交不推进回合，失败也不能发送会推进6080的4206。
local protocol = require("core.protocol")
local M = {}
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
