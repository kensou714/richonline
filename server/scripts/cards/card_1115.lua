-- 武器条约（资源编号 1115）。本文件是该卡的独立业务入口。
-- C2S 操作号 142；request.payload 是未加密的完整内部报文，包含操作号。
-- 武器条约清除全部活动角色主手牌中的五类武器整叠，保留其余卡槽。
-- 经典会话绑定全员库存事务；当前单真人BOSS会话绑定真人手牌库存。
-- C2S142/S2C40DE 都是 6 字节，扣本卡和移除武器在同一库存事务内生效。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1115, name = "武器条约", opcode = 142, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 6, "武器条约请求长度错误")
    core.call("card.prepare", { card = M.id })
    -- 7F8FF0的固定清除表：地雷、定时炸弹、飞弹、核弹、安全核弹。
    core.call("inventory.prepare_clear", { cards = { 1044, 1045, 1046, 1063, 1075 } })
    return { protocol.inner(0x40DE, request.game_id, request.payload:sub(5)) }
end
return M
