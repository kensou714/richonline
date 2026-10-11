-- 经典模式的13槽节日业务。随机输入来自权威卡池/随机源，Lua不直接改账本或发包。
-- 与BOSS最大的区别：春节发8000现金，元宵出院、中秋出狱；不能套用BOSS的180点券。
local M = {}
local gifts = { [1]=true, [2]=true, [4]=true, [5]=true, [9]=true }
local fixed_tickets = { [0]=111, [8]=55, [11]=99 }
local harmful = { [1]=true, [2]=true, [6]=true, [7]=true, [18]=true }
function M.plan(request)
    local slot = request.slot
    assert(math.type(slot) == "integer" and slot >= 0 and slot < 13, "节日槽无效")
    local effects = core.array()
    for _, actor in ipairs(request.actors) do
        local tickets = fixed_tickets[slot] or 0
        if slot == 3 then
            assert(actor.luck == 0 or actor.luck == 1, "愚人节结果无效")
            tickets = actor.luck == 1 and 41 or -41
        end
        local release = 0
        if slot == 7 and actor.hospital ~= -1 then release = 1 end
        if slot == 10 and actor.jail ~= -1 then release = 2 end
        effects[#effects + 1] = {
            actor=actor.actor, cash=slot == 6 and 8000 or 0, tickets=tickets,
            card=gifts[slot] and actor.card or -1, release=release,
            detach=slot == 12 and harmful[actor.possession] == true, clear_bomb=slot == 12,
        }
    end
    return { opcode=gifts[slot] and 0x40A0 or (slot == 3 and 0x40A1 or 0), effects=effects }
end
return M
