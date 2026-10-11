-- 保险卡（资源编号 1049）。本文件是该卡的独立业务入口。
-- 本卡没有主动TCP请求；经典住院的被动赔付由hospital准备，核心原子提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local M = { id = 1049, name = "保险卡", opcode = nil, reward_enabled = false, implementation = "passive_hospital" }
-- 动画9结束按天数减一赔付；资格来自CARD类型和地图，自动使用不检查Prop.enable。
function M.hospital(event)
    assert(math.type(event.days) == "integer" and event.days >= 1 and event.days <= 127,
        "住院天数必须为正的signed BYTE")
    assert(#event.slots == 8, "保险必须核对八个手牌槽")
    local inventory, selected = {}, -1
    for index, slot in ipairs(event.slots) do
        inventory[index] = {card = slot.card, count = slot.count}
        if event.insurance_eligible and selected == -1 and slot.card == 1049 then
            assert(slot.count > 0, "保险卡数量无效")
            selected = index - 1
            inventory[index].count = slot.count - 1
            if inventory[index].count == 0 then inventory[index].card = -1 end
        end
    end
    assert(not event.insurance_eligible or selected >= 0 or event.secondary_insurance_absent,
        "尚未确认第二套保险卡库存")
    -- 一天住院仍消耗一张保险卡，即使赔付为0；同叠剩余卡不重复使用。
    local compensation = selected >= 0 and 2500 * (event.days - 1) or 0
    return {cash = event.cash + compensation, insurance_slot = selected,
        compensation = compensation, inventory = inventory}
end
return M
