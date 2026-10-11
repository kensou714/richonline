-- 黑贝贝 BOSS 独立规则入口。
-- actionable 由核心根据停留、指定步数、乌龟、梦游、冻结、睡神等权威状态计算。
-- 本层决定 AI 是否尝试攻击，核心战斗事务还会核验目标格/库存/伤害，不能跳过状态约束。
-- 地雷/飞弹/核弹由下列独立概率控制，随黑贝贝自己的关卡递增。
local M = { name = "黑贝贝" }
function M.frenzy_rules(stage)
    if stage ~= 4 then return nil end
    -- 原客户端第二组防御下降按受伤倍率增加计算：下降75%对应1.75倍伤害。
    return { hp_percent = 10, attack_percent = 50, damage_percent = 75, talk_group = 4, talk_index = 8 }
end
function M.probabilities(stage)
    local extra = (stage - 1) * 2
    return {math.min(100, 20 + extra), math.min(100, 15 + extra), math.min(100, 10 + extra)}
end
function M.can_attack(request) return request.actionable end
-- 兼容旧的boss.attack调用；生产战斗读取probabilities，每种武器只判定一次。
-- roll 是核心均匀产生的 0..99，所有二次随机都使用同一核心随机源。
function M.attack(request)
    if request.roll < 80 then return nil end
    if request.roll < 90 then return request.mine end
    local choices = request.projectiles
    assert(#choices > 0, "缺少 BOSS 武器")
    local index = #choices == 1 and 1 or core.call("random", { upper = #choices })
    return choices[index]
end
return M
