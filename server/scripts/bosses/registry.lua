-- BOSS 注册与地图关联。增加独立 BOSS 后在这里注册，再由地图模块引用。
local maps = require("maps.registry")
local bosses = {
    heibeibei = require("bosses.heibeibei"), azhanbo = require("bosses.azhanbo"),
    kid_ken = require("bosses.kid_ken"), zhao_linger = require("bosses.zhao_linger"),
}
local M = {}
function M.attack(request)
    local map = assert(maps[request.map], "未注册地图：" .. request.map)
    return assert(bosses[map.boss], "未注册 BOSS").attack(request)
end
function M.can_attack(request)
    local map = assert(maps[request.map], "未注册地图：" .. request.map)
    return assert(bosses[map.boss], "未注册 BOSS").can_attack(request)
end
return M
