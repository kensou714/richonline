-- 红色新闻格：Lua 选择已准备候选；核心负责 BwNews 颜色过滤与事务提交。
local news = require("tiles.news_select")
local landing = require("tiles.news_landing")
local M = { type = 69, implementation = "lua" }
function M.land(request) return landing.land(request) end
function M.select_news(request) return news.select(request, M.type) end
return M
