-- 对局网络生命周期。准入令牌、加密和重放门由 EXE 校验后才进入此模块。
-- 此处返回外层 Frame 数组；卡片业务在 game.session 中返回内部明文包。
local M = {}
function M.request(request) return core.call("network.native") end
function M.admitted() return core.array() end
function M.poll() return core.array() end
function M.sent(request) end
function M.disconnected() end
return M
