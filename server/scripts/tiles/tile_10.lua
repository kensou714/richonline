-- 静态格类型 10 的独立落点入口；type 是 EMP 静态类型，不是道路位置编号。
-- 核心准备货架但不打开商店；Lua组织完整回包后才允许写会话和启动计时。
local protocol = require("core.protocol")
local M = { type = 10, implementation = "lua" }
function M.land(request)
    local supported = false
    for _, capability in ipairs(core.capabilities()) do
        if capability == "tile.shop.prepare" then supported = true end
    end
    if not supported or not request.shop_landing_available then return core.call("tile.native") end
    local plan = core.call("tile.shop.prepare")
    local messages = {protocol.inner(0x4013, request.game_id, string.pack("<i2", request.position))}
    if plan.open then
        assert(#plan.offers == 12 and #plan.opaque == 2, "商店货架格式无效")
        local rows = {}
        for _, offer in ipairs(plan.offers) do
            rows[#rows + 1] = string.pack("<i2i2BB", offer.card, offer.count, plan.opaque[1], plan.opaque[2])
        end
        -- 最后一字节0表示首次开店；刷新计费与买卖仍由既有等待状态机接续。
        messages[#messages + 1] = protocol.inner(0x4030, request.game_id, table.concat(rows) .. string.char(0))
    end
    return messages
end
return M
