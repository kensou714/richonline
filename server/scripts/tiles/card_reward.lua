-- 赠卡格共享编排。选卡和4013/4029顺序在Lua；资源、合成和库存版本由核心复核。
local protocol = require("core.protocol")
local M = {}
function M.land(request, fixed_card)
    local supported = false
    for _, capability in ipairs(core.capabilities()) do
        if capability == "tile.cards.prepare" then supported = true end
    end
    -- BOSS没有手牌，受控角色按原流程跳过赠卡；旧EXE在任何准备前回退。
    if not supported or not request.card_reward_allowed then return core.call("tile.native") end
    local candidates = core.call("tile.cards.candidates")
    assert(#candidates > 0, "赠卡格候选为空")
    local card
    if fixed_card then
        assert(#candidates == 1 and candidates[1] == fixed_card, "固定赠卡与资源策略不一致")
        card = fixed_card
    else
        card = candidates[core.call("tile.random", { upper = #candidates }) + 1]
    end
    core.call("tile.cards.prepare", { card = card })
    -- 满手牌仍提示抽中的卡并继续；不重抽，实际是否入手及合成由准备器决定。
    return {
        protocol.inner(0x4013, request.game_id, string.pack("<i2", request.position)),
        protocol.inner(0x4029, request.game_id, string.pack("<i2", card)),
    }
end
return M
