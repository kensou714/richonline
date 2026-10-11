-- 涨价卡（资源编号 1058）。本文件是该卡的独立业务入口。
-- C2S 操作号 119；request.payload 是未加密的完整内部报文，包含操作号。
-- 脚下同街区普通地产表成员重设五天标记，初始种类8/9/10不在此表；来源也拒绝这些种类。
-- 经典模式按日期递减，住宅逐块贡献先除1000再翻倍，商店不翻倍；查封仍优先免租。
-- 标记与查封独立，不随换屋转移；模式3不额外产生经典租金或递减计时。
-- 脚本组织请求/回包，地产版本校验和标记变更由核心与扣卡共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1058, name = "涨价卡", opcode = 119, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 6, "涨价卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    core.call("property.prepare", { operation = "price_rise" })
    return { protocol.inner(0x40C7, request.game_id, request.payload:sub(5)) }
end
return M
