-- 账号背包装备规则。part 序号来自客户端 7FF1D0 的 A675C0 表，不能使用商城分类代替。
-- 这里只规划资格；完整道具键的归属、有效期和槽位旧值由数据库事务再次验证。
local parts = {
    "PET", "VEHICLE", "LAND", "DENG", "DICE", "MOVE", "BACK", "SUIT",
    "GLASS", "COVER", "MASK", "KITBAG", "GOWITH", "POCKET", "ROLE_PLANE",
    "HOUSE_PLANE", "5_ROLE", "6_ROLE", "7_ROLE", "8_ROLE", "9_ROLE",
    "1_BOSS", "2_BOSS", "3_BOSS", "4_BOSS", "5_BOSS", "6_BOSS",
    "7_BOSS", "8_BOSS", "9_BOSS", "10_BOSS",
}
local M = {}
function M.plan(request)
    local function refuse(reason) return { allowed = false, reason = reason } end
    if request.opcode == 52 then
        -- 卸下使用客户端查询到的完整旧键，不得只比较低 12 位商品编号。
        if request.item ~= request.current then return refuse("equipment_stale") end
        return { allowed = true }
    end
    if request.product == nil or request.product == core.null then return refuse("equipment_product_missing") end
    if parts[request.slot + 1] ~= request.product.part then return refuse("equipment_part_mismatch") end
    if request.current ~= 0 then return refuse("equipment_slot_occupied") end
    if request.level < request.product.level then return refuse("equipment_level_required") end
    if not request.product.role_allowed then return refuse("equipment_character_not_allowed") end
    return { allowed = true }
end
return M
