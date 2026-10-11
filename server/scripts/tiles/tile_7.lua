-- 静态格7：正常玩家获30点券，BOSS及受控角色跳过。
local reward = require("tiles.ticket_reward")
local M = { type = 7, implementation = "lua" }
function M.land(request) return reward.land(request, 30) end
return M
