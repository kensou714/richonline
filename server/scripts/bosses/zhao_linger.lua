-- 赵灵儿 BOSS 独立规则入口。
-- actionable 由核心根据停留、指定步数、乌龟、梦游、冻结、睡神等权威状态计算。
-- 本层决定 AI 是否尝试攻击，核心战斗事务还会核验目标格/库存/伤害，不能跳过状态约束。
-- 当前攻击实现仍是共享原生兼容 AI；专属技能尚未迁移，不宣称已经完整复刻。
local M = { name = "赵灵儿" }
function M.can_attack(request) return request.actionable end
-- 四次攻击尝试由核心驱动；每次按 80% 待机、10% 地雷、10% 投射武器选择。
-- 武器候选由本地图允许列表提供（黑贝贝不含安全核弹），不猜测额外技能。
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
