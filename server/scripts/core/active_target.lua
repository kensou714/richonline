-- 目标角色请求的共享解码：+6 是零基角色槽，+7 是客户端附带的保留字节。
-- 同盟、察看、清除和飞吻只允许指定仍在场的角色；不从报文推断角色身份或资金。
local M = {}
function M.decode(request)
    assert(#request.payload == 8, "目标角色请求长度错误")
    local target = request.payload:byte(7)
    local snapshot = core.call("game.snapshot")
    local person = snapshot.actors[target + 1]
    assert(person and person.active, "目标角色不在场")
    return target
end
-- 这些目标卡现有成功响应都将保留字节归零，防止客户端收到未验证的附带参数。
function M.response_body(request)
    return request.payload:sub(5, 7) .. string.char(0)
end
-- 移动状态卡共享入口：C++ motion.prepare 复用原生道路/动态物件/状态时钟计划器。
function M.motion(request, card_id)
    assert(#request.payload == 8, "移动卡请求长度错误")
    local target = request.payload:byte(7)
    local plan = core.call("card.prepare", { card = card_id })
    assert(plan.slot >= 0, "移动卡槽位无效")
    local prepared = core.call("motion.prepare", { card = card_id, target = target })
    local result = { prepared.response }
    for _, packet in ipairs(prepared.movement) do result[#result + 1] = packet end
    for _, packet in ipairs(prepared.recovery) do result[#result + 1] = packet end
    return result
end
return M
