-- 路障卡（资源编号 1043）。本文件是该卡的独立业务入口。
-- C2S 操作号 108；request.payload 是未加密的完整内部报文，包含操作号。
-- 放置 NPC 11；元数据 byte7=request.actor、byte8=255，不覆盖已有物件。
-- 地面计划与扣卡共同提交，踩到物件后的移动/爆炸处理继续读取同一核心地面状态。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local ground = require("core.ground")
local M = { id = 1043, name = "路障卡", opcode = 108, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 8, "路障卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    local position = string.unpack("<i2", request.payload, 7)
    ground.prepare(position, 11, request.actor, 255)
    return { protocol.inner(0x40BC, request.game_id, request.payload:sub(5)) }
end
return M
