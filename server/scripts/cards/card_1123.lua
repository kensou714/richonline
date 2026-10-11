-- 认购卡（资源编号 1123）。本文件是该卡的独立业务入口。
-- C2S 操作号 150；request.payload 是未加密的完整内部报文，包含操作号。
-- 经典会话已配置股票时默认按买方存款尽量收购；用户已明确确认此数量规则。
-- 目标已卖光时零数量确认不扣卡，买不起时由会话恢复操作，不伪报目标卖光。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local M = { id = 1123, name = "认购卡", opcode = 150, reward_enabled = false, implementation = "native_compatibility" }
local protocol = require("core.protocol")
function M.quantity(request)
    local price, deposit = request.price, request.buyer_deposit
    local low, high = 0, math.min(request.seller_holding, 2147483647 - request.buyer_holding)
    local function float(value) return string.unpack("<f", string.pack("<f", value)) end
    -- 预算按现价限制整股；实际扣款仍须经过与C++成交内核一致的单精度舍入。
    while low < high do
        local middle = low + (high - low + 1) // 2
        local total = float(price * float(middle))
        if price * middle <= deposit and total <= 2147483647 and math.floor(total) <= deposit then
            low = middle
        else
            high = middle - 1
        end
    end
    return low
end
function M.transfer(request)
    local quantity, amount = request.quantity, request.amount
    local buyer_deposit, seller_deposit = request.buyer_deposit, request.seller_deposit
    -- 客户端先存成float再乘75%，避免把float乘积再次取整到单精度。
    local rounded_amount = string.unpack("<f", string.pack("<f", amount))
    local payout = math.floor(rounded_amount * 0.75)
    local reason = "accepted"
    if quantity > 2147483647 then reason = "quantity_limit"
    elseif quantity == 0 and request.seller_holding ~= 0 then reason = "quantity_required"
    elseif quantity > request.seller_holding then reason = "insufficient_holding"
    elseif not request.amount_valid then reason = "amount_limit"
    elseif buyer_deposit < amount then reason = "insufficient_deposit"
    elseif payout > 2147483647 - seller_deposit then reason = "deposit_limit"
    elseif quantity > 2147483647 - request.buyer_holding then reason = "holding_limit" end
    local accepted, message = reason == "accepted", ""
    if accepted then
        buyer_deposit, seller_deposit = buyer_deposit - amount, seller_deposit + payout
        -- 目标卖光后的零数量确认也覆写双方存款，但客户端不会扣卡。
        message = protocol.inner(0x40e6, request.game_id,
            string.pack("<i1I1i1I1i2I2i4i4i4i4", request.inventory_slot, 0,
                request.target, 0, request.stock_slot, 0, quantity, amount, buyer_deposit, seller_deposit))
    end
    return {accepted = accepted, reason = reason, consumes_card = accepted and quantity ~= 0, message = message}
end
function M.use(request)
    -- 请求已经过网络身份验证；具体槽位、回合、目标合法性仍由核心事务核验。
    -- 迁移本卡时可以改为调用细粒度核心接口；禁止重复调用 game.native 导致重复扣卡。
    return core.call("game.native")
end
return M
