-- 静态格类型 28 的独立落点入口；type 是 EMP 静态类型，不是道路位置编号。
-- 地图配对由核心读取；Lua只确认入口，客户端自行执行成对传送动画。
local portal = require("tiles.portal_landing")
local M = { type = 28, implementation = "lua" }
function M.land(request) return portal.land(request) end
return M
