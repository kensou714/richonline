-- 强抛卡（资源编号 1124）。本文件是该卡的独立业务入口。
-- C2S 操作号 151；request.payload 是未加密的完整内部报文，包含操作号。
-- 股票尚未接入实际对局：use仍恢复控件；liquidate供已绑定股票内核准备原子计划。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local M = { id = 1124, name = "强抛卡", opcode = 151, reward_enabled = false, implementation = "native_compatibility" }
local protocol = require("core.protocol")
function M.liquidate(request)
    local reason, returned, deposits = "accepted", 0, {}
    for index, actor in ipairs(request.actors) do
        local deposit = actor.deposit
        if actor.active then
            returned = returned + actor.quantity
            if not actor.amount_valid then
                if reason == "accepted" then reason = "amount_limit" end
            elseif actor.amount > 2147483647 - deposit then
                if reason == "accepted" then reason = "deposit_limit" end
            else deposit = deposit + actor.amount end
        end
        deposits[index] = deposit
    end
    if reason == "accepted" and returned > 2147483647 - request.supply then reason = "supply_limit" end
    local accepted, message = reason == "accepted", ""
    if accepted then
        -- 40E7直接清仓，包括零持仓使用；存款数组保留已淘汰角色的原槽。
        local body = string.pack("<i1I1i2", request.inventory_slot, 0, request.stock_slot)
        for _, deposit in ipairs(deposits) do body = body .. string.pack("<i4", deposit) end
        message = protocol.inner(0x40e7, request.game_id, body)
    end
    return {accepted = accepted, reason = reason, message = message}
end
function M.use(request)
    -- 请求已经过网络身份验证；具体槽位、回合、目标合法性仍由核心事务核验。
    -- 迁移本卡时可以改为调用细粒度核心接口；禁止重复调用 game.native 导致重复扣卡。
    return core.call("game.native")
end
return M
