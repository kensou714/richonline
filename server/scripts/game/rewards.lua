-- 卡片格/福神/新闻/节日的共享随机池，按地图资源筛选可售卖且已实现的卡。
-- 新核心 candidates 已取 Prop.enable/typeCARD、EMP membership 与商店出售价格表交集。
-- Lua 应用业务开放规则，核心还会再次过滤返回值；无法出售的卡不能借脚本重新进入随机池。
-- 不把未实现的股票/开店卡或无主动行为的资源自动加入奖励。
local cards = require("cards.registry")
local maps = require("maps.registry")
local M = {}
function M.pool(request)
    local result = core.array()
    local map = assert(maps[request.map], "未注册的奖励地图")
    for _, id in ipairs(map.reward_pool(request.candidates)) do
        -- 500 系列是商城金豆商品；商城货架卡不能从棋盘随机卡片格产生。
        -- 过滤只作用于随机奖励候选，商店购买/出售仍使用独立货架规则。
        local mall_gold_card = id >= 500 and id <= 519
        local card = cards.by_id[id]
        if card and card.reward_enabled and not mall_gold_card then result[#result + 1] = id end
    end
    assert(#result > 0, "当前地图没有可用随机卡片")
    return result
end
return M
