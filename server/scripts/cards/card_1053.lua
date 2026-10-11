-- 抢夺卡（资源编号 1053）。本文件是该卡的独立业务入口。
-- C2S 操作号 116；request.payload 是未加密的完整内部报文，包含操作号。
-- 经典模式由transfer编排抢夺和防盗；核心按双方快照原子提交库存。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local M = { id = 1053, name = "抢夺卡", opcode = 116, reward_enabled = true, implementation = "native_compatibility" }
local protocol = require("core.protocol")
local protection = require("cards.card_1074")
function M.transfer(request)
    local protected = protection.select(request)
    local selected = request.inventory[request.target_slot + 1]
    assert(selected and selected.card > 0 and selected.count > 0, "抢夺目标卡槽为空")
    return {
        protection_slot = protected,
        transferred_card = protected >= 0 and -1 or selected.card,
        message = protocol.inner(0x40C4, request.game_id,
            string.pack("<I1I1I1I1", request.inventory_slot, 0, request.target, request.target_slot)),
    }
end
function M.use(request)
    -- BOSS入口仍走原兼容路由：合成BOSS没有权威手牌，返回400B且不扣卡。
    return core.call("game.native")
end
return M
