-- 免罪卡（资源编号 1057）。本文件是该卡的独立业务入口。
-- 无主动TCP请求；指定坐牢新闻在入狱前调用，成功后不触发住院/保险效果。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local M = { id = 1057, name = "免罪卡", opcode = nil, reward_enabled = false, implementation = "passive_jail" }
local insurance = require("cards.card_1049")
function M.jail(event)
    assert(math.type(event.days) == "integer" and event.days >= 1 and event.days <= 127,
        "入狱天数必须为正的signed BYTE")
    assert(#event.slots == 8, "免罪必须核对八个手牌槽")
    local inventory, selected = {}, -1
    for index, slot in ipairs(event.slots) do
        inventory[index] = {card = slot.card, count = slot.count}
        if event.pardon_eligible and selected == -1 and slot.card == 1057 then
            assert(slot.count > 0, "免罪卡数量无效")
            selected = index - 1
            inventory[index].count = slot.count - 1
            if inventory[index].count == 0 then inventory[index].card = -1 end
        end
    end
    if selected >= 0 then
        return {jail = -1, stay = event.stay, cash = event.cash, pardon_slot = selected,
            insurance_slot = -1, compensation = 0, inventory = inventory}
    end
    assert(not event.pardon_eligible or event.secondary_pardon_absent, "第二套免罪卡尚未核实")
    -- 动画11与住院动画9共用保险结束回调；免罪失败时才准备这笔赔付。
    local result = insurance.hospital(event)
    result.jail, result.stay, result.pardon_slot = event.days, 0, -1
    return result
end
return M
