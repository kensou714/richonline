-- 目标攻击卡的共同编排。Lua解析请求、准备扣卡和战斗、生成确认；核心统一提交伤害和终局。
local protocol = require("core.protocol")
local M = {}
function M.use(request, card, confirmation, projectile)
    local can_prepare = false
    for _, name in ipairs(core.capabilities()) do
        if name == "combat.prepare_attack" then can_prepare = true end
    end
    -- 安装EXE可能仍在使用旧快照，必须在任何准备动作之前进入原生兼容分支。
    if not can_prepare then return core.call("game.native") end
    assert(#request.payload == (projectile and 10 or 8), "攻击卡请求长度错误")
    if projectile then
        assert(request.payload:byte(9) == 0 and request.payload:byte(10) == 1,
            "攻击卡请求构造字段错误")
    end
    local target = string.unpack("<i2", request.payload, 7)
    assert(target >= 0, "攻击卡目标格错误")
    core.call("card.prepare", { card = card })
    core.call("combat.prepare_attack", { card = card, target = target })
    local payload = request.payload:sub(5, 8)
    -- 请求尾部0/1不是响应尾部；客户端确认需要实际施放者及普通手牌攻击标记0。
    if projectile then payload = payload .. string.pack("BB", request.actor, 0) end
    return { protocol.inner(confirmation, request.game_id, payload) }
end
return M
