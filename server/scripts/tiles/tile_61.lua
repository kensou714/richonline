-- 静态格类型 61 的独立落点入口；type 是 EMP 静态类型，不是道路位置编号。
-- 这里只处理最终落点；途经61的步进传送仍属于核心路线验证。
local portal = require("tiles.portal_landing")
local M = { type = 61, implementation = "lua" }
function M.land(request) return portal.land(request) end
return M
