-- 六步卡（资源编号 1084）。本文件是该卡的独立业务入口。
-- C2S 操作号 141；request.payload 是未加密的完整内部报文，包含操作号。
-- 当前复杂效果使用原生兼容事务，库存、状态与响应须由同一次操作共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local motion = require("core.active_target")
local M = { id = 1084, name = "六步卡", opcode = 141, reward_enabled = true, implementation = "lua" }
function M.use(request) return motion.motion(request, M.id) end
return M
