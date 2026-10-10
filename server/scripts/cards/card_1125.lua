-- 洗牌卡（资源编号 1125）。本文件是该卡的独立业务入口。
-- C2S 操作号 152；request.payload 是未加密的完整内部报文，包含操作号。
-- Lua 决定已有卡叠的随机顺序；核心按同一顺序重放客户端插入/合成并原子提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 1125, name = "洗牌卡", opcode = 152, reward_enabled = true, implementation = "lua" }
function M.use(request)
    -- 源码脚本目录也供已安装的旧 EXE 读取；旧核心沿用已交付的原生洗牌事务。
    local can_reorder = false
    for _, name in ipairs(core.capabilities()) do
        if name == "inventory.prepare_reorder" then can_reorder = true end
    end
    if not can_reorder then return core.call("game.native") end

    assert(#request.payload == 6, "洗牌卡请求长度错误")
    local consumed = core.call("card.prepare", { card = M.id })
    local stacks = core.call("inventory.consumed_snapshot")
    -- Fisher–Yates 只改变卡叠顺序，不凭空生成新卡；一张洗牌卡已在准备快照中扣除。
    for size = #stacks, 2, -1 do
        local selected = core.call("random", { upper = size })
        assert(math.type(selected) == "integer" and selected >= 1 and selected <= size, "洗牌随机值无效")
        stacks[size], stacks[selected] = stacks[selected], stacks[size]
    end
    local order = core.array()
    local body = { string.pack("<I1I1I1I1", consumed.slot, consumed.bank, #stacks, 0) }
    for _, stack in ipairs(stacks) do
        order[#order + 1] = stack.slot
        body[#body + 1] = string.pack("<I2I1I1", stack.card, stack.count, request.actor)
    end
    -- 空手牌也提交空数组；重复、缺失、空槽或越界槽均由核心拒绝且不扣卡。
    core.call("inventory.prepare_reorder", { slots = order })
    return { protocol.inner(0x40E8, request.game_id, table.concat(body)) }
end
return M
