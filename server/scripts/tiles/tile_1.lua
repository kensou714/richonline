-- 经典机会/新闻格。抽取策略来自已绑定当前地图的宿主，不能套用BOSS的4096表。
-- 本文件只准备金额、停走、灾难和报文；状态、地产及全员结算由会话统一提交。
local protocol = require("core.protocol")
local insurance = require("cards.card_1049")
local M = {}
local income = {[0x406d] = true, [0x406e] = true}
local plain = {[0x406d] = true, [0x4070] = true, [0x4073] = true, [0x4074] = true,
    [0x4075] = true, [0x4076] = true, [0x4079] = true, [0x407c] = true}
local pictured = {[0x406e] = true, [0x4071] = true, [0x4077] = true, [0x407a] = true,
    [0x407b] = true, [0x407d] = true, [0x407e] = true, [0x4094] = true, [0x4095] = true}
function M.land(request)
    if not request.classic_news_available then return core.call("tile.native") end
    local event = core.call("tile.classic_news.prepare")
    if event.opcode == 0x407f or event.opcode == 0x4087 then
        local plan = insurance.hospital(event)
        plan.hospital, plan.stay = event.days, 0
        plan.messages = {
            protocol.inner(0x4013, request.game_id, string.pack("<i2", request.position)),
            protocol.inner(event.opcode, request.game_id, string.pack("<i2b", event.picture, event.days)),
        }
        return plan
    end
    if event.opcode == 0x4081 then
        assert(math.type(event.days) == "integer" and event.days >= 1 and event.days <= 127,
            "绑架天数必须为正的signed BYTE")
        -- 动画14只写1497并清stay；没有免罪、保险、清附身或转移产权。
        return {kidnapped = event.days, stay = 0, messages = {
            protocol.inner(0x4013, request.game_id, string.pack("<i2", request.position)),
            protocol.inner(0x4081, request.game_id, string.pack("<i2b", event.picture, event.days)),
        }}
    end
    if event.opcode >= 0x408b and event.opcode <= 0x408f then
        local kind, level = event.kind, event.level
        if level > 0 and kind ~= 8 and kind ~= 9 and kind ~= 10 then
            level = math.max(0, level - (event.opcode == 0x408b and 1 or 5))
            if level == 0 then kind = event.sprite == 11 and 0 or -1 end
        end
        -- 新闻目标是地产表索引，既不要求当前玩家所有，也不转移原有产权。
        local payload = event.opcode == 0x408f and string.pack("<i2", event.property)
            or string.pack("<i2i2", event.picture, event.property)
        return {kind = kind, level = level, owner = event.owner, messages = {
            protocol.inner(0x4013, request.game_id, string.pack("<i2", request.position)),
            protocol.inner(event.opcode, request.game_id, payload),
        }}
    end
    if event.opcode == 0x4072 then
        assert(math.type(event.duration) == "integer" and event.duration >= 1 and event.duration <= 127,
            "豪雨停走必须使用GValue中的有效时长")
        local stays = {}
        for index, player in ipairs(event.players) do
            local eligible = player.active and player.hotel == -1 and player.hospital == -1
                and player.jail == -1 and player.kidnapped == -1
            -- 原事件直接覆盖1496；不加一，不叠加，也不检查攻击卡免疫。
            stays[index] = eligible and event.duration or player.stay
        end
        return {stays = stays, messages = {
            protocol.inner(0x4013, request.game_id, string.pack("<i2", request.position)),
            protocol.inner(0x4072, request.game_id, ""),
        }}
    end
    if event.opcode == 0x4078 then
        local tickets, inventory = event.tickets, {}
        assert(#event.slots == 8, "新闻变卖必须提供八个手牌槽")
        for index, slot in ipairs(event.slots) do
            if slot.card ~= -1 then
                -- 原客户端整叠只加一次完整资源价格，与普通商店出售规则不同。
                tickets = tickets + slot.price
            end
            inventory[index] = {card = -1, count = 0}
        end
        return {tickets = tickets, inventory = inventory, messages = {
            protocol.inner(0x4013, request.game_id, string.pack("<i2", request.position)),
            protocol.inner(0x4078, request.game_id, ""),
        }}
    end
    if event.opcode == 0x406f then
        -- 存款第一名按全部活动槽比较：并列不分摊，全零也各领完整金额。
        assert(math.type(event.amount) == "integer" and event.amount >= 0 and event.amount <= 32767,
            "新闻金额超出有符号WORD")
        local highest, funds, recipients = 0, {}, {}
        for _, player in ipairs(event.players) do
            if player.active then highest = math.max(highest, player.deposit) end
        end
        for index, player in ipairs(event.players) do
            local cash = player.cash
            if player.active and player.deposit == highest then
                cash = cash + event.amount
                recipients[#recipients + 1] = index - 1
            end
            funds[index] = {cash = cash, deposit = player.deposit}
        end
        return {funds = funds, recipients = recipients, messages = {
            protocol.inner(0x4013, request.game_id, string.pack("<i2", request.position)),
            protocol.inner(0x406f, request.game_id, string.pack("<i2i2", event.picture, event.amount)),
        }}
    end
    assert(plain[event.opcode] or pictured[event.opcode], "经典金额新闻类型未实现")
    assert(math.type(event.amount) == "integer" and event.amount >= 0 and event.amount <= 32767,
        "新闻金额超出有符号WORD")
    local cash, deposit, fines = event.cash, event.deposit, event.fines
    local bankrupt = not income[event.opcode] and cash + deposit <= event.amount
    if income[event.opcode] then
        cash = cash + event.amount
    else
        local paid = math.min(cash, event.amount)
        cash = cash - paid
        deposit = math.max(0, deposit - (event.amount - paid))
        fines = fines + event.amount
    end
    local payload
    if pictured[event.opcode] then
        assert(event.picture >= 0 and event.picture < 100, "新闻图索引无效")
        payload = string.pack("<i2i2", event.picture, event.amount)
    else
        assert(event.picture == -1, "纯文字新闻不能携带图索引")
        payload = string.pack("<i2", event.amount)
    end
    return {cash = cash, deposit = deposit, fines = fines, bankrupt = bankrupt, messages = {
        protocol.inner(0x4013, request.game_id, string.pack("<i2", request.position)),
        protocol.inner(event.opcode, request.game_id, payload),
    }}
end
function M.return_kidnapped(request)
    assert(math.type(request.position) == "integer" and request.position >= 0 and request.position <= 32767,
        "绑架返回位置超出signed WORD")
    -- 4008先排606C重定位，再用反向动画14清1497，最后608A阶段6恢复行动。
    return {position = request.position, kidnapped = -1,
        message = protocol.inner(0x4008, request.game_id, string.pack("<i2", request.position))}
end
return M
