-- 防盗卡（资源编号 1074）。本文件是该卡的独立业务入口。
-- 本卡没有主动 TCP 使用请求；保留独立资源定义，供被动效果消费者查询。
-- 经典抢夺消费者调用select决定主手牌防盗槽，核心将双方扣卡放在同一次事务提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local M = { id = 1074, name = "防盗卡", opcode = nil, reward_enabled = false, implementation = "native_compatibility" }
-- 7F85C0按槽位从小到大搜索；目标选中了防盗卡本身时也先消耗防盗、阻止抢夺。
function M.select(request)
    if not request.protection_eligible then return -1 end
    for index, slot in ipairs(request.inventory) do
        if slot.card == M.id then
            assert(slot.count > 0, "防盗卡数量无效")
            return index - 1
        end
    end
    assert(request.secondary_protection_absent, "第二套防盗卡库存未核实")
    return -1
end
return M
