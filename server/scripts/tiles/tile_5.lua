-- 静态格5：正常玩家获80点券，BOSS及受控角色跳过。
local reward = require("tiles.ticket_reward")
local M = { type = 5, implementation = "lua" }
function M.land(request) return reward.land(request, 80) end
return M
