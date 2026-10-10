-- 停留卡（资源编号 1041）。本文件是该卡的独立业务入口。
-- C2S 操作号 106；request.payload 是未加密的完整内部报文，包含操作号。
-- Lua 负责入口；库存、状态时钟与响应仍由核心在同一事务中提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local motion = require("core.active_target")
local M = { id = 1041, name = "停留卡", opcode = 106, reward_enabled = true, implementation = "lua" }
function M.use(request) return motion.motion(request, M.id) end
return M
