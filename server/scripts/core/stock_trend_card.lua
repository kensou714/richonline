-- 行情卡共用编排：只登记未来三次波动，价格由整局行情策略在波动发生时给出。
local protocol = require("core.protocol")
local M = {}
function M.use(request, id, single, direction)
    if request.mode ~= 0 then return core.call("game.native") end
    assert(#request.payload == (single and 8 or 6), "行情卡请求长度错误")
    core.call("card.prepare", {card = id})
    local trends = core.call("stock.trend_snapshot")
    local target = single and string.unpack("<i2", request.payload, 7) or nil
    assert(not single or (target >= 0 and target < #trends), "股票槽无效")
    for slot, row in ipairs(trends) do
        if not single or slot == target + 1 then
            -- 明确的服务端覆盖策略，不将其声称为已恢复的原服叠加算法。
            row.direction, row.remaining = direction, 3
        end
    end
    core.call("stock.prepare_trends", {trends = trends})
    return {protocol.inner(0x40e2 + id - 1119, request.game_id, request.payload:sub(5))}
end
return M
