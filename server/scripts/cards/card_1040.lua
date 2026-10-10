-- 转向卡（资源编号 1040）。本文件是该卡的独立业务入口。
-- C2S 操作号 105；request.payload 是未加密的完整内部报文，包含操作号。
-- Lua 负责卡牌入口和请求回包；核心移动计划器继续验证反向道路、路障、地雷和落点续接。
-- 成功回包与路线均由共享核心移动计划器构造，Lua 不复制棋盘拓扑。
local motion = require("core.active_target")
local M = { id = 1040, name = "转向卡", opcode = 105, reward_enabled = true, implementation = "lua" }
function M.use(request) return motion.motion(request, M.id) end
return M
