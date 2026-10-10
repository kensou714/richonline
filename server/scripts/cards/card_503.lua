-- 换位卡（资源编号 503）。本文件是该卡的独立业务入口。
-- C2S 操作号 161；request.payload 是未加密的完整内部报文，包含操作号。
-- 换位卡仅在仍在场、没有冰冻、原始旅馆/医院/监狱/绑架状态均可行动的角色之间轮换位置。
-- 资格与当前坐标由核心提供；Lua 选择轮换顺序，所有角色坐标与本卡扣除共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 503, name = "换位卡", opcode = 161, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 6, "换位卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    local eligible = core.array()
    for _, person in ipairs(core.call("actor.relocation_snapshot")) do
        if person.active and person.raw_available and not person.frozen then
            eligible[#eligible + 1] = person
        end
    end
    assert(#eligible >= 2, "可换位角色不足")
    local positions = core.array()
    for index, person in ipairs(eligible) do
        local next_person = eligible[index % #eligible + 1]
        positions[#positions + 1] = { actor = person.slot, position = next_person.position }
    end
    core.call("actor.prepare_positions", { positions = positions })
    return { protocol.inner(0x40F1, request.game_id, request.payload:sub(5)) }
end
return M
