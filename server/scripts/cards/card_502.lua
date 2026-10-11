-- 净空卡（资源编号 502）。本文件是该卡的独立业务入口。
-- C2S 操作号 160；request.payload 是未加密的完整内部报文，包含操作号。
-- 6 字节请求不带目标。净空清除动态物件，原客户端7E28B0保留NPC32胜利宝箱。
-- 静态道路和地产不受影响；Lua 决定移除集合，核心将地面变化与扣卡共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local protocol = require("core.protocol")
local M = { id = 502, name = "净空卡", opcode = 160, reward_enabled = true, implementation = "lua" }
function M.use(request)
    assert(#request.payload == 6, "净空卡请求长度错误")
    core.call("card.prepare", { card = M.id })
    assert(core.call("game.snapshot").can_act, "当前角色不能使用净空卡")
    local positions = core.array()
    for _, object in ipairs(core.call("ground.snapshot")) do
        if object.npc ~= 32 then positions[#positions + 1] = object.position end
    end
    -- 空地图仍消耗一张卡并确认成功。读取和移除使用同一原始版本，失败不扣卡。
    core.call("ground.prepare_remove", { positions = positions })
    -- 40F0 让客户端自行清空动态记录，不逐格额外发送生成/销毁通知。
    return { protocol.inner(0x40F0, request.game_id, request.payload:sub(5)) }
end
return M
