-- 静态格6：正常玩家获50点券，BOSS及受控角色跳过。
local reward = require("tiles.ticket_reward")
local M = { type = 6, implementation = "lua" }
function M.land(request) return reward.land(request, 50) end
return M
