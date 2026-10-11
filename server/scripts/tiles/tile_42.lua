-- 静态格42：沿用已开放的固定赠卡1046策略。
-- 当前固定赠卡规则不冒充原服务器未恢复的抽奖算法。
local reward = require("tiles.card_reward")
local M = { type = 42, implementation = "lua" }
function M.land(request) return reward.land(request, 1046) end
return M
