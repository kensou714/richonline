-- 认购卡（资源编号 1123）。本文件是该卡的独立业务入口。
-- C2S 操作号 150；request.payload 是未加密的完整内部报文，包含操作号。
-- 普通股票对局尚未接入；transfer接收核心明确的成交数量，不在这里猜测数量策略。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local M = { id = 1123, name = "认购卡", opcode = 150, reward_enabled = false, implementation = "native_compatibility" }
local protocol = require("core.protocol")
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
