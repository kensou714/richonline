-- 新闻落点编排：核心准备期间仅消耗随机数，不提交资金、库存或状态。
-- Lua 必须完整返回4013、4096两帧；核心逐字节验证后才原子提交。
local protocol = require("core.protocol")
local M = {}
function M.land(request)
    local supported = false
    for _, capability in ipairs(core.capabilities()) do
        if capability == "tile.news.prepare" then supported = true end
    end
    -- 旧核心及不能触发新闻的落点在准备前回退。梦游BOSS是否触发由核心判断。
    if not supported or not request.news_landing_available then return core.call("tile.native") end
    local event = core.call("tile.news.prepare")
    assert(type(event) == "string" and #event >= 4, "新闻事件报文缺失")
    local opcode, game = string.unpack("<I2I2", event)
    assert(opcode == 0x4096 and game == request.game_id, "新闻事件报文身份不一致")
    return {
        protocol.inner(0x4013, request.game_id, string.pack("<i2", request.position)),
        event,
    }
end
return M
