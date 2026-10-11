-- 嫁祸卡（资源编号 1056）。本文件是该卡的独立业务入口。
-- 租金/type1贸易中心/type2饭店被动触发后，用0076/40C6完成一次选人；饭店仍由原玩家入住。
-- 核心持有待决快照，校验资格，并把库存和两步资金变更一起提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local M = { id = 1056, name = "嫁祸卡", opcode = nil, reward_enabled = false, implementation = "native_compatibility" }
function M.rent(request)
    local target = request.timed_out and -1 or request.choice
    assert(target == -1 or (target ~= request.original_payer and request.eligible[target + 1]), "嫁祸目标无效")
    local payer = target == -1 and request.original_payer or target
    local source, recipient = request.balances[payer + 1], request.balances[request.recipient + 1]
    local charged = math.min(request.amount, source.cash + source.deposit)
    local credited = recipient.deposit + charged
    local cash_paid = math.min(charged, source.cash)
    local cash = source.cash - cash_paid
    local deposit = (payer == request.recipient and credited or source.deposit) - (charged - cash_paid)
    return {
        target = target, payer = payer, charged = charged, consume_card = target ~= -1,
        bankrupt = cash == 0 and deposit == 0, credited_deposit = credited,
        payer_cash = cash, payer_deposit = deposit,
        message = string.pack("<I2I2b", 0x40C6, request.game_id, target),
    }
end
return M
