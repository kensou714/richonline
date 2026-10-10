-- 乐透卡（资源编号 504）。本文件是该卡的独立业务入口。
-- C2S 操作号 162；request.payload 是未加密的完整内部报文，包含操作号。
-- 本卡规则和回包由 Lua 实现，核心负责校验回合、准备扣卡并原子提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 504, name = "乐透卡", opcode = 162, reward_enabled = true, implementation = "lua" }
-- 乐透现金属于明确的模拟器配置，修改此数值无需重新编译 EXE；核心负责溢出和原子提交。
function M.award() return 15000 end
function M.use(request)
    -- 请求已经过网络身份验证；具体槽位、回合、目标合法性仍由核心事务核验。
    -- 迁移本卡时可以改为调用细粒度核心接口；禁止重复调用 game.native 导致重复扣卡。
    -- 扣卡和加现金都只生成计划，完整构造 12 字节回包后由宿主共同提交。
    assert(#request.payload == 6, "乐透卡长度错误")
    local use = core.call("card.prepare", { card = M.id })
    local award = M.award()
    core.call("funds.prepare", { actor = request.actor, cash = award })
    return { protocol.inner(0x40F2, request.game_id, string.pack("<I1I1I2I4", use.slot, use.bank, 0, award)) }
end
return M
