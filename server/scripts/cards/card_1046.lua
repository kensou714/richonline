-- 飞弹卡（资源编号 1046）。本文件是该卡的独立业务入口。
-- C2S 操作号 111；request.payload 是未加密的完整内部报文，包含操作号。
-- Lua编排目标攻击与确认；核心在同一战斗事务中提交库存、伤害和地面/地产变化。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local attack = require("core.attack_card")
local M = { id = 1046, name = "飞弹卡", opcode = 111, reward_enabled = true, implementation = "lua" }
function M.use(request)
    return attack.use(request, M.id, 0x40BF, true)
end
return M
