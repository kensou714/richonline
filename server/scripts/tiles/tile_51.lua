-- 静态格51：沿用已开放的固定赠卡1182策略。
-- 当前固定赠卡规则不冒充原服务器未恢复的抽奖算法。
local reward = require("tiles.card_reward")
local M = { type = 51, implementation = "lua" }
function M.land(request) return reward.land(request, 1182) end
return M
