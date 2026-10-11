-- 服务端 Lua 主模块（API v1）。所有正式事件在此分发，新增事件必须明确注册。
-- require 仅加载 server/scripts 发布快照；禁止系统命令、本地 DLL 和客户端目录依赖。
-- 修改文件后 scripts.reload 只影响新连接/新对局，旧对局使用原版本直到结束。
assert(core.api_version == 1, "Lua 核心接口版本不匹配")
local lobby = require("network.lobby")
local network = require("network.game")
local game = require("game.session")
local rewards = require("game.rewards")
local feasts = require("events.feasts")
local tiles = require("tiles.registry")
local bosses = require("bosses.registry")
local boss_chest = require("bosses.chest")
local lottery = require("cards.card_504")
local mall_purchase = require("mall.purchase")
local equipment = require("mall.equipment")
local equipment_effects = require("mall.equipment_effects")
local handlers = {
    ["lobby.login"] = lobby.login, ["lobby.request"] = lobby.request,
    ["lobby.poll"] = lobby.poll, ["lobby.sent"] = lobby.sent, ["lobby.disconnected"] = lobby.disconnected,
    ["network.game"] = network.request, ["network.admitted"] = network.admitted,
    ["network.poll"] = network.poll, ["network.sent"] = network.sent, ["network.disconnected"] = network.disconnected,
    ["game.action"] = game.action, ["rewards.pool"] = rewards.pool, ["feast.tickets"] = feasts.tickets,
    ["tile.land"] = tiles.land, ["tile.news_select"] = tiles.select_news,
    ["boss.can_attack"] = bosses.can_attack,
    ["card.lottery_award"] = lottery.award,
    ["boss.attack"] = bosses.attack,
    ["boss.chest_select"] = boss_chest.select,
    ["mall.purchase_policy"] = mall_purchase.plan,
    ["mall.equipment_policy"] = equipment.plan,
    ["mall.equipment_healing"] = equipment_effects.healing,
}
local M = {}
function M.dispatch(event, request)
    local handler = assert(handlers[event], "未注册 Lua 事件：" .. event)
    return handler(request)
end
return M
