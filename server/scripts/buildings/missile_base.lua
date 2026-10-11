-- 飞弹基地的完整轮周期和逐发选点。PAO 资源、产权、控制状态及真实伤害由核心提供/校验。
-- 本模块不持有局内状态；返回计划后，由原有战斗事务一次提交时钟、资金、地产和地面物。
local M = {}

function M.clock(request)
    local remaining, period = request.remaining, request.period
    assert(math.type(remaining) == "integer" and remaining >= 0 and remaining <= 127, "基地剩余周期无效")
    assert(math.type(period) == "integer" and period >= 1 and period <= 127, "基地资源周期无效")
    -- 新登记的0只装载周期，不立即发射。升级不重置已有倒计时；下次装载采用新等级资源。
    local fire = remaining == 1
    if remaining > 0 then remaining = remaining - 1 end
    if remaining == 0 then remaining = period end
    return { remaining = remaining, fire = fire }
end

function M.target(request)
    -- 核心按道路/地雷/敌人/NPC分类，且在上一弹伤害和连锁爆炸后重新产生候选。
    -- 候选顺序与重复位置的权重保持原样；空池、受控BOSS及死亡后的停射由核心处理。
    local positions = request.positions
    assert(type(positions) == "table" and #positions > 0, "基地目标候选为空")
    local draw = core.call("building.missile_random", { bound = #positions })
    assert(math.type(draw) == "integer" and draw >= 0 and draw < #positions, "基地目标随机数越界")
    local position = positions[draw + 1]
    assert(math.type(position) == "integer" and position >= 0 and position <= 32767, "基地目标位置无效")
    return position
end

return M
