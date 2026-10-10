-- 大厅网络事件入口。每条连接独立 Lua VM，模块局部变量可保存连接状态。
-- 用户身份来自原生认证结果，不能采信报文里自报的 username。
local mall = require("mall.service")
local M = {}
function M.request(request)
    if request.opcode == 16 or request.opcode == 18 or request.opcode == 63 then
        return mall.request(request)
    end
    return core.call("lobby.native")
end
function M.login(request) return core.call("lobby.native") end
function M.poll() return core.array() end
function M.sent(request) end
function M.disconnected() end
return M
