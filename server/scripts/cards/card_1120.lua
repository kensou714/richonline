-- 黑卡（资源编号 1120）。本文件是该卡的独立业务入口。
-- C2S 操作号 147；request.payload 是未加密的完整内部报文，包含操作号。
-- 经典模式登记单股连续三次下跌；确认包只扣卡，不即时改价。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local M = { id = 1120, name = "黑卡", opcode = 147, reward_enabled = false, implementation = "lua" }
local trend = require("core.stock_trend_card")
function M.use(request)
    return trend.use(request, M.id, true, -1)
end
return M
