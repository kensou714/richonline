-- 静态格类型 58 的独立落点入口；type 是 EMP 静态类型，不是道路位置编号。
-- 使用核心提供的道路候选和一次随机索引，编排4013入口确认与4209重定位。
local portal = require("tiles.portal_landing")
local M = { type = 58, implementation = "lua" }
function M.land(request) return portal.land(request) end
return M
