-- 静态格8：从地图允许且可出售的卡池均匀抽一张。
local reward = require("tiles.card_reward")
local M = { type = 8, implementation = "lua" }
function M.land(request) return reward.land(request) end
return M
