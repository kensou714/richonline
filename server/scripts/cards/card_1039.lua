-- 乌龟卡（资源编号 1039）。本文件是该卡的独立业务入口。
-- C2S 操作号104；目标角色在+6。核心复用移动计划器处理路障、地雷和落点续接。
local motion = require("core.active_target")
local M = { id = 1039, name = "乌龟卡", opcode = 104, reward_enabled = true, implementation = "lua" }
function M.use(request) return motion.motion(request, M.id) end
return M
