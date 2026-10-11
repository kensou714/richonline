-- 静态格54：沿用已开放的固定赠卡1038策略。
-- 当前固定赠卡规则不冒充原服务器未恢复的抽奖算法。
local reward = require("tiles.card_reward")
local M = { type = 54, implementation = "lua" }
function M.land(request) return reward.land(request, 1038) end
return M
