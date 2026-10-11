-- 用户确认的BOSS专属规则。随机数由本局核心提供，Lua不直接写地图或账本。
local maps = require("maps.registry")
local M = {}
function M.plan(request)
    local map = assert(maps[request.map], "未注册地图")
    local stage = tonumber(request.map:match("BS_%d+_(%d+)%.emp$"))
    assert(stage and stage >= 1, "BOSS关卡无效")
    if request.event == "negative_possession" then
        local npc = request.npc
        if request.sleepwalking or request.frozen or
            (npc ~= 1 and npc ~= 2 and npc ~= 6 and npc ~= 7 and npc ~= 18) then return 0 end
        if core.call("random", {upper = 100}) > math.min(100, 30 + (stage - 1) * 5) then return 0 end
        return 4 + core.call("random", {upper = 3})
    end
    if request.event == "fire" then
        if map.boss == "heibeibei" or request.sleepwalking or request.frozen then return 0 end
        if core.call("random", {upper = 100}) > 20 then return 0 end
        return 4 + core.call("random", {upper = 3})
    end
    error("未注册BOSS技能")
end
return M
