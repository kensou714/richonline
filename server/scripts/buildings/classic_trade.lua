-- 贸易中心kind3。UI15只显示1..6；结果概率由准入策略提供，不能由客户端请求指定。
-- 此模块仅报价/编码。核心复核状态后统一处理免费卡、嫁祸、资金与破产续行。
local M = {}
local function signed32(value)
    value = value & 0xFFFFFFFF
    return value >= 0x80000000 and value - 0x100000000 or value
end
function M.plan(request)
    local result = request.result
    assert(result == -1 or (result >= 1 and result <= 6), "贸易中心结果无效")
    local amount = signed32(signed32(signed32(request.scale * request.level) * 600) * result)
    if request.price_rise_days > 0 then amount = signed32(amount * 2) end
    return {
        quote = result == -1 and 0 or amount,
        message = string.pack("<I2I2b", 0x4027, request.game_id, result),
    }
end
return M
