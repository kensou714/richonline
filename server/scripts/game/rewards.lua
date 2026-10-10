-- 卡片格/福神/节日的共享随机池。旧实现只允许四张移动卡，现按地图资源筛选已实现卡。
-- candidates 来自原生 Prop.enable/typeCARD 与 EMP membership 交集；此处再应用业务开放规则。
-- 不把未实现的股票/开店卡或无主动行为的资源自动加入奖励。
local cards = require("cards.registry")
local maps = require("maps.registry")
local M = {}
function M.pool(request)
    local result = core.array()
    local map = assert(maps[request.map], "未注册的奖励地图")
    for _, id in ipairs(map.reward_pool(request.candidates)) do
        local card = cards.by_id[id]
        if card and card.reward_enabled then result[#result + 1] = id end
    end
    assert(#result > 0, "当前地图没有可用随机卡片")
    return result
end
return M
