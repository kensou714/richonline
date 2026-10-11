-- 关卡原生恢复：4010已经驱动客户端本地回血，业务只提交服务端镜像，不额外发包。
-- amount_float由核心按客户端的单精度存储转换，乘积在Lua双精度域计算并取整。
local M = {}
function M.plan(request)
    if not request.eligible or request.cash >= request.cap then
        return {amount = 0, consume_eligibility = false}
    end
    local amount = request.amount
    if request.frenzy then amount = math.floor(request.amount_float * request.factor + 0.5) end
    return {amount = math.min(amount, request.cap - request.cash), consume_eligibility = true}
end
return M
