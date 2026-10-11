-- 经典地产的已授权选择。落点资格、身份、日历和资金提交由C++核心统一持有。
local M = {}
function M.choose(request)
    assert(request.choice == 0x20 or request.choice == 0x21, "经典地产选择类型无效")
    local accepted, outcome = false, "declined"
    if request.timed_out then
        outcome = "timed_out"
    elseif request.requested then
        if request.cash <= request.cost then
            outcome = "insufficient_funds"
        else
            accepted, outcome = true, "accepted"
        end
    end
    local owner, level = request.owner, request.level
    -- 状态2确认后仍花费现金，但产权和等级保持原状。
    if accepted and not request.select_building and request.possession ~= 2 then
        if request.choice == 0x20 then owner = request.actor else level = level + 1 end
    end
    return {
        accepted = accepted, charged = accepted and not request.select_building and request.cost or 0, outcome = outcome,
        owner = owner, level = level,
        message = string.pack("<I2I2B", request.choice + 0x4000, request.game_id, accepted and 1 or 0),
    }
end
-- 普通升级第二阶段：4025只带选择；客户端据此自行扣钱、扣许可证并排6073。
function M.building(request)
    local selected = request.timed_out and 3 or request.requested
    assert(selected == -1 or (selected >= 2 and selected <= 6), "建筑种类无效")
    local outcome = request.timed_out and "timed_out" or (selected == -1 and "declined" or "accepted")
    if selected ~= -1 and request.cash <= request.cost then
        selected, outcome = -1, "insufficient_funds"
    elseif selected ~= -1 and request.licence_required and not request.licence_owned then
        selected, outcome = -1, "licence_missing"
    end
    local kind, level = request.kind, request.level
    if selected ~= -1 and request.possession ~= 2 then kind, level = selected, level + 1 end
    return {
        selected = selected, charged = selected ~= -1 and request.cost or 0, outcome = outcome,
        kind = kind, level = level, consume = selected ~= -1 and request.licence_required,
        message = string.pack("<I2I2b", 0x4025, request.game_id, selected),
    }
end
-- NEW x86每次乘法取低32位，住宅先逐块有符号除1000，最后累加。
local function signed32(value)
    value = value & 0xFFFFFFFF
    return value >= 0x80000000 and value - 0x100000000 or value
end
function M.rent_quote(request)
    assert(request.kind == 0 or request.kind == 1, "租金地产类型无效")
    local coefficients = {500, 1000, 2500, 5000, 8000, 12500}
    local total = 0
    for _, item in ipairs(request.items) do
        local amount
        if request.kind == 0 then
            local product = signed32(signed32(item.price * request.scale) * coefficients[item.level + 1])
            amount = product >= 0 and product // 1000 or -((-product) // 1000)
            -- D+5只翻倍这块住宅的贡献，先除后倍，不能把整个街区结果统一翻倍。
            if item.price_rise_days > 0 then amount = signed32(amount * 2) end
        else
            amount = signed32(request.scale * 4000)
        end
        total = signed32(total + amount)
    end
    return total
end
function M.rent_payment(request)
    local amount, free_slot, outcome = request.quote, -1, "paid"
    if request.suppressed or request.possession == 0 then
        amount, outcome = 0, "waived"
    else
        if request.possession == 1 then amount = signed32(amount * 2) end
        for index, card in ipairs(request.inventory) do
            if amount >= 5000 and request.free_eligible and card.card == 1050 then
                free_slot, outcome = index - 1, "free_card"
                break
            end
        end
        if outcome == "paid" then
            for _, card in ipairs(request.inventory) do
                if amount >= 10000 and request.transfer_eligible and card.card == 1056 then
                    outcome = "transfer_pending"
                    break
                end
            end
        end
        if outcome == "paid" and amount >= request.cash + request.deposit then outcome = "bankrupt" end
    end
    return {amount = amount, free_slot = free_slot, outcome = outcome}
end
return M
