-- 福神卡（资源编号 1070）。本文件是该卡的独立业务入口。
-- C2S 操作号 131；request.payload 是未加密的完整内部报文，包含操作号。
-- Lua编排福神附身与两张奖励；核心按扣卡后的库存顺序抽取、插入和合成。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1070, name = "福神卡", opcode = 131, reward_enabled = true, implementation = "lua" }
function M.use(request)
    local can_attach = false
    for _, name in ipairs(core.capabilities()) do
        if name == "npc.prepare_attach" then can_attach = true end
    end
    if not can_attach then return core.call("game.native") end
    assert(#request.payload == 6, "福神卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    core.call("npc.prepare_attach", { npc = 3 })
    local cards = core.call("inventory.prepare_fortune")
    assert(#cards == 2, "福神奖励数量错误")
    -- 40D3替换旧附身；4023随后按顺序发两张卡。客户端本地续接，不等待额外ACK。
    return {
        protocol.inner(0x40D3, request.game_id, request.payload:sub(5, 6)),
        protocol.inner(0x4023, request.game_id, string.pack("<I2I2", cards[1], cards[2])),
    }
end
return M
