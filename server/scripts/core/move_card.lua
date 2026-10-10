-- 立即移动卡的共享事务编排；步数和确认消息号由各卡牌模块决定。
-- 与一步/六步状态卡不同，本模块没有目标角色，不新增持续状态。
-- card.prepare 校验当前回合、日历、库存槽和卡号，只准备消耗一张卡。
-- route.prepare_move 生成真实道路上的 4011 路线；路障、香蕉和过路交互由核心处理。
-- 两步都只准备状态，脚本返回且回包校验通过后才一起提交；报错保留原手牌。
local protocol = require("core.protocol")
local M = {}
function M.use(request, card_id, response_opcode, steps)
    local consumed = core.call("card.prepare", { card = card_id })
    local movement = core.call("route.prepare_move", { steps = steps })
    -- 先确认客户端扣卡，再播放移动；核心要求完整、按原顺序返回路线，禁止漏包。
    local result = { protocol.inner(response_opcode, request.game_id,
        string.char(consumed.slot, consumed.bank)) }
    for _, packet in ipairs(movement) do result[#result + 1] = packet end
    return result
end
return M
