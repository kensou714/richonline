-- 查封卡（资源编号 1035）。本文件是该卡的独立业务入口。
-- C2S 操作号 100；request.payload 是未加密的完整内部报文，包含操作号。
-- 当前角色脚下同街区的地产设置五天标记；模式3不额外产生经典租金或递减计时。
-- 脚本组织请求/回包，地产版本校验和标记变更由核心与扣卡共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1035, name = "查封卡", opcode = 100, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 6, "查封卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    core.call("property.prepare", { operation = "seal" })
    return { protocol.inner(0x40B4, request.game_id, request.payload:sub(5)) }
end
return M
