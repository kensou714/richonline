-- 大地产12：落点、产权和建筑附加效果仍由核心续接；建造/升级/研究选择在本模块。
-- 所有方法只返回计划，核心逐字段核对后才写入建筑、许可证和研究队列。
local protocol = require("core.protocol")
local M = { type = 12, implementation = "native_compatibility", decisions = "lua" }
function M.land(request) return core.call("tile.native") end

function M.construct(request)
    local selection, licence_slot = request.selection, -1
    assert(selection == -1 or (selection >= 10 and selection <= 20), "建筑选择无效")
    -- -1是默认建筑请求，403D不能原样回-1；10才是取消。
    if selection == -1 then selection = request.default_kind end
    if request.synthetic then
        assert(request.owner == 1 and request.level == 0, "BOSS建造快照无效")
        selection = request.default_kind
    elseif selection ~= 10 then
        local index = selection - 10
        if request.owner ~= 0 or request.level ~= 0 or
            (selection ~= request.default_kind and request.caps[index] == 0) then
            selection = 10
        elseif selection ~= request.default_kind then
            -- 客户端消耗第一叠匹配许可证；槽号返回零基，不按卡号重新排序。
            for index, item in ipairs(request.inventory) do
                if item.card == request.licences[selection - 10] and item.count > 0 then
                    licence_slot = index - 1
                    break
                end
            end
            if licence_slot == -1 then selection = 10 end
        end
    end
    return {selection = selection, licence_slot = licence_slot,
        message = protocol.inner(0x403D, request.game_id, string.pack("b", selection))}
end

function M.upgrade(request)
    assert(request.kind >= 11 and request.kind <= 20, "升级建筑种类无效")
    local owner = request.synthetic and 1 or 0
    local accept = request.accept and request.owner == owner and request.level > 0 and
        request.level < request.cap and request.level < request.skill
    local continuation = "complete"
    if not request.synthetic and request.kind == 11 then continuation = "research"
    elseif request.kind == 16 then continuation = "temple"
    elseif request.kind == 15 then continuation = "garden" end
    -- 拒绝升级也必须继续研究/神庙/花园；403E不扣现金和许可证。
    return {accept = accept, level = request.level + (accept and 1 or 0), continuation = continuation,
        message = protocol.inner(0x403E, request.game_id, string.pack("B", accept and 1 or 0))}
end

function M.research(request)
    local selection, jobs = request.selection, core.array()
    if selection ~= -1 then
        assert(selection >= 1 and selection <= 7 and request.owner == 0 and request.kind == 11 and
            selection <= request.level, "研究选择不可用")
        -- 同一选择最多排三份，使用队列前面的空槽；满队列不覆盖旧任务。
        -- 原客户端把倍数天数存成有符号BYTE，必须保留截断语义。
        for cycle = 1, math.min(3, #request.free_slots) do
            jobs[#jobs + 1] = {slot = request.free_slots[cycle], property = request.property,
                choice = selection, card = request.card, days = (request.days * cycle + 128) % 256 - 128}
        end
    end
    return {selection = selection, jobs = jobs,
        message = protocol.inner(0x403F, request.game_id, string.pack("b", selection))}
end
return M
