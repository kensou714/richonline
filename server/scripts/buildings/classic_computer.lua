-- 电脑公司：落点收费由客户端4013自动触发，服务端只同步账本，不重复发送金额事件。
local M = {}
function M.quote(request)
    local amount = (request.level * 150 * request.scale) & 0xFFFFFFFF
    if request.price_rise_days > 0 then amount = (amount * 2) & 0xFFFFFFFF end
    return amount >= 0x80000000 and amount - 0x100000000 or amount
end
return M
