-- 梦游卡（资源编号 1042）。本文件是该卡的独立业务入口。
-- C2S 操作号 107；request.payload 是未加密的完整内部报文，包含操作号。
-- Lua 负责卡牌入口；核心移动计划器继续处理梦游状态时钟、保护卡和自动移动。目标为自己时由核心恢复掷骰续接。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local motion = require("core.active_target")
local M = { id = 1042, name = "梦游卡", opcode = 107, reward_enabled = true, implementation = "lua" }
function M.use(request) return motion.motion(request, M.id) end
return M
