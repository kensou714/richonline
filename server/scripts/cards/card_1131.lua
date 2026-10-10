-- 星光环绕（资源编号 1131）。本文件是该卡的独立业务入口。
-- C2S 操作号 168；request.payload 是未加密的完整内部报文，包含操作号。
-- 本卡规则和回包由 Lua 实现，核心负责校验回合、准备扣卡并原子提交。
-- 星光环绕不能在局内出售，不进入卡片格等共享随机奖励池；已有卡仍可正常使用。
local protocol = require("core.protocol")
local M = { id = 1131, name = "星光环绕", opcode = 168, reward_enabled = false, implementation = "lua" }
function M.use(request)
    -- 请求已经过网络身份验证；具体槽位、回合、目标合法性仍由核心事务核验。
    -- 迁移本卡时可以改为调用细粒度核心接口；禁止重复调用 game.native 导致重复扣卡。
    -- 仅视效与扣卡。核心在脚本完整返回并验证报文后提交库存；异常不扣卡。
    assert(#request.payload == 6, "视效卡长度错误")
    local use = core.call("card.prepare", { card = M.id })
    return { protocol.inner(16632, request.game_id, string.pack("<I1I1", use.slot, use.bank)) }
end
return M
