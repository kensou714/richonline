-- 飞吻（资源编号 1130）。本文件是该卡的独立业务入口。
-- C2S 操作号 167；request.payload 是未加密的完整内部报文，包含操作号。
-- 飞吻是只播动画的卡，服务端不添加关系或目标状态。
-- C2S167 的目标在 +6；S2C40F7 的 +7 保留字节归零，库存扣除与回包共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local active_target = require("core.active_target")
local M = { id = 1130, name = "飞吻", opcode = 167, reward_enabled = true, implementation = "lua" }
function M.use(request)
    active_target.decode(request)
    core.call("card.prepare", { card = M.id })
    return { protocol.inner(0x40F7, request.game_id, active_target.response_body(request)) }
end
return M
