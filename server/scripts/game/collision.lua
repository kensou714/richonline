-- 落点phase6的同格业务；只返回转移意图，不操作库存或网络。
-- C++先验证身份/原始状态，复核本表后按客户端插入和合成规则一次提交所有玩家。
local M = {}
function M.plan(request)
    local owner = assert(request.actors[request.actor + 1], "当前同格角色不存在")
    local result = { evaluate_junction = true, transfers = core.array() }
    if request.suppressed or (request.mode == 4 and owner.synthetic) then
        result.evaluate_junction = false
        return result
    end
    if owner.synthetic or owner.possession ~= 6 then return result end
    -- 必须按玩家槽顺序，逐人读取第一个非空手牌槽；接收方满手也不豁免来源扣卡。
    for _, other in ipairs(request.actors) do
        if other.slot ~= owner.slot and other.active and not other.synthetic and not other.excluded
            and other.position == owner.position then
            for index, slot in ipairs(other.inventory) do
                if slot.card ~= -1 then
                    result.transfers[#result.transfers + 1] = {
                        source_actor = other.slot, target_actor = owner.slot,
                        source_slot = index - 1, card_id = slot.card,
                    }
                    break
                end
            end
        end
    end
    return result
end
return M
