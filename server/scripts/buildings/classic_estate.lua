-- 房产公司使用Map+46C的确定顺序；候选只读，实际地产提交由核心事务负责。
local M = {}
function M.plan(request)
    local selected
    for group = 0, request.improve and 1 or 2 do
        local threshold = request.level
        for _, item in ipairs(request.candidates) do
            local category
            if group == 0 then category = item.sprite == 11 and item.kind == 0
            elseif not request.improve and group == 1 then category = item.sprite == 11 and item.kind == 1
            else category = item.sprite == 12 end
            if category and item.owner == request.actor and (not request.improve or item.id ~= request.source) then
                local eligible = request.improve and item.level < threshold
                    or not request.improve and item.level > 0 and item.level <= threshold
                if eligible then selected, threshold = item, item.level end
            end
        end
        if selected then break end
    end
    if not selected then return {target = -1, kind = -1, level = 0} end
    local kind, level = selected.kind, selected.level
    if request.improve then
        if selected.sprite == 12 and (kind < 2 or kind > 6) then kind = 3 end
        level = math.min(5, level + request.level)
    else
        kind, level = selected.sprite == 11 and 0 or -1, 0
    end
    return {target = selected.id, kind = kind, level = level}
end
return M
