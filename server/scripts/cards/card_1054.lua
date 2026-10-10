-- 陷害卡（资源编号 1054）。本文件是该卡的独立业务入口。
-- C2S 操作号 117；request.payload 是未加密的完整内部报文，包含操作号。
-- 当前复杂效果使用原生兼容事务，库存、状态与响应须由同一次操作共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local M = { id = 1054, name = "陷害卡", opcode = 117, reward_enabled = true, implementation = "native_compatibility" }
function M.use(request)
    -- 请求已经过网络身份验证；具体槽位、回合、目标合法性仍由核心事务核验。
    -- 迁移本卡时可以改为调用细粒度核心接口；禁止重复调用 game.native 导致重复扣卡。
    return core.call("game.native")
end
return M
