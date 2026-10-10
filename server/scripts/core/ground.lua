-- 地面放置共享规则：供路障、香蕉、超级地雷等独立卡片调用。
-- position 是棋盘格号；地面 NPC 和静态格是两层状态，不能覆盖已有 NPC。
-- 核心提供真实道路、角色占用和可用范围；Lua 决定本类卡的静态格禁放集合。
-- 2/3 为特殊出入口，28/58/61 为传送入口；与当前客户端和原生放置规则保持一致。
local M = {}
local forbidden = { [2] = true, [3] = true, [28] = true, [58] = true, [61] = true }
function M.prepare(position, npc, byte7, byte8)
    local cell = core.call("map.cell", { position = position })
    assert(cell.walkable, "目标不是道路")
    assert(cell.ground_visible, "目标不在允许范围")
    assert(not cell.actor_occupied, "目标有角色")
    assert(not forbidden[cell.static_type], "该静态格禁止放置")
    -- 只生成带版本的计划。若脚本之后失败，地面和手牌都保持原样。
    core.call("ground.prepare", { position = position, npc = npc, byte7 = byte7, byte8 = byte8 })
end
return M
