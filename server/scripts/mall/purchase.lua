-- 商城购买策略：服务端从 Prop/SellProp 副本解析商品，只将已上架且可用的条目交给本模块。
-- 本模块不访问 SQL、不扣款、不发货；它只返回资格与有效期计划，失败时核心发送原有错误响应。
-- 客户端商品键中的年份仅有 4 位，必须按当前部署的日期纪元检查，不能截断后伪造购买成功。
local M = {}
local function refuse(reason)
    return { allowed = false, reason = reason }
end
function M.plan(request)
    -- 套装的逐件入库和等级门槛尚未完成协议闭环，不能按单件处理或无条件放开。
    if request.fold ~= 1 then return refuse("mall_purchase_bundle_grant_unproven") end
    if request.level ~= 0 then return refuse("mall_purchase_level_rule_unproven") end
    assert(request.currency == 1 or request.currency == 2, "商城币种无效")
    assert(request.date_epoch == 2005 or request.date_epoch == 2021, "商城日期纪元无效")
    local expiry = core.call("mall.calendar_expiry", request.term)
    if expiry.expires_at ~= 0 and
        (expiry.year < request.date_epoch or expiry.year > request.date_epoch + 15) then
        return refuse("inventory_date_year_unrepresentable")
    end
    -- 价格/期限必须与客户端资源一致。核心再次核验期限，并在 SQL 事务里读取真实余额。
    -- 只有事务成功后才发物品通知和角色余额刷新，不能在这里自行返回成功回包。
    return { allowed = true, expires_at = expiry.expires_at }
end
return M
