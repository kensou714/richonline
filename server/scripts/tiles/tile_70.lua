-- 黄色新闻格：Lua 选择已准备候选；核心负责 BwNews 颜色过滤与事务提交。
local news = require("tiles.news_select")
local M = { type = 70, implementation = "lua_selection_native_transaction" }
function M.land(request) return core.call("tile.native") end
function M.select_news(request) return news.select(request, M.type) end
return M
