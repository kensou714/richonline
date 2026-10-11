-- BOSS 注册与地图关联。增加独立 BOSS 后在这里注册，再由地图模块引用。
local maps = require("maps.registry")
local bosses = {
    heibeibei = require("bosses.heibeibei"), azhanbo = require("bosses.azhanbo"),
    kid_ken = require("bosses.kid_ken"), zhao_linger = require("bosses.zhao_linger"),
}
local M = {}
function M.frenzy_rules(request)
    local map = assert(maps[request.map], "未注册地图：" .. request.map)
    local boss = assert(bosses[map.boss], "未注册 BOSS")
    local stage = assert(tonumber(request.map:match("BS_%d+_(%d+)%.emp$")), "BOSS关卡编号无效")
    return boss.frenzy_rules and boss.frenzy_rules(stage) or nil
end
function M.probabilities(request)
    local map = assert(maps[request.map], "未注册地图：" .. request.map)
    local boss = assert(bosses[map.boss], "未注册 BOSS")
    local stage = tonumber(request.map:match("BS_%d+_(%d+)%.emp$"))
    assert(stage and stage >= 1, "BOSS关卡编号无效")
    return boss.probabilities and boss.probabilities(stage) or nil
end
function M.attack(request)
    local map = assert(maps[request.map], "未注册地图：" .. request.map)
    return assert(bosses[map.boss], "未注册 BOSS").attack(request)
end
function M.can_attack(request)
    local map = assert(maps[request.map], "未注册地图：" .. request.map)
    return assert(bosses[map.boss], "未注册 BOSS").can_attack(request)
end
return M
