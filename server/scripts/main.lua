-- 服务端 Lua 主模块（API v1）。所有正式事件在此分发，新增事件必须明确注册。
-- require 仅加载 server/scripts 发布快照；禁止系统命令、本地 DLL 和客户端目录依赖。
-- 修改文件后 scripts.reload 只影响新连接/新对局，旧对局使用原版本直到结束。
assert(core.api_version == 1, "Lua 核心接口版本不匹配")
local lobby = require("network.lobby")
local network = require("network.game")
local game = require("game.session")
local rewards = require("game.rewards")
local stock = require("game.stock")
local collision = require("game.collision")
local classic_retirement = require("game.classic_retirement")
local classic_settlement = require("game.classic_settlement")
local feasts = require("events.feasts")
local classic_feasts = require("events.classic_feasts")
local tiles = require("tiles.registry")
local classic_news = require("tiles.tile_1")
local classic_lottery = require("tiles.tile_4")
local bank = require("tiles.tile_9")
local property = require("tiles.tile_12")
local missile_base = require("buildings.missile_base")
local classic_property = require("buildings.classic_property")
local classic_research = require("buildings.classic_research")
local bosses = require("bosses.registry")
local boss_chest = require("bosses.chest")
local boss_skills = require("bosses.skills")
local lottery = require("cards.card_504")
local rent_transfer = require("cards.card_1056")
local forced_sale = require("cards.card_1124")
local subscription = require("cards.card_1123")
local mall_purchase = require("mall.purchase")
local mall_consumables = require("mall.consumables")
local mall_bags = require("mall.bags")
local equipment = require("mall.equipment")
local equipment_effects = require("mall.equipment_effects")
local handlers = {
    ["mall.bag_award"] = mall_bags.award,
    ["lobby.login"] = lobby.login, ["lobby.request"] = lobby.request,
    ["lobby.poll"] = lobby.poll, ["lobby.sent"] = lobby.sent, ["lobby.disconnected"] = lobby.disconnected,
    ["network.game"] = network.request, ["network.admitted"] = network.admitted,
    ["network.poll"] = network.poll, ["network.sent"] = network.sent, ["network.disconnected"] = network.disconnected,
    ["game.action"] = game.action, ["rewards.pool"] = rewards.pool, ["feast.tickets"] = feasts.tickets,
    ["feast.classic"] = classic_feasts.plan,
    ["tile.land"] = tiles.land, ["tile.news_select"] = tiles.select_news,
    ["tile.classic_kidnap_return"] = classic_news.return_kidnapped,
    ["lottery.purchase"] = classic_lottery.purchase, ["lottery.draw"] = classic_lottery.draw,
    ["bank.open"] = bank.open, ["bank.transaction"] = bank.transaction,
    ["property.construct"] = property.construct, ["property.upgrade"] = property.upgrade,
    ["property.research"] = property.research,
    ["building.missile_clock"] = missile_base.clock,
    ["building.missile_target"] = missile_base.target,
    ["property.classic_choice"] = classic_property.choose,
    ["property.classic_building"] = classic_property.building,
    ["property.classic_research_choice"] = classic_research.choose,
    ["property.classic_research_scan"] = classic_research.scan,
    ["property.classic_rent_quote"] = classic_property.rent_quote,
    ["property.classic_rent_payment"] = classic_property.rent_payment,
    ["collision.plan"] = collision.plan,
    ["game.classic_retirement"] = classic_retirement.plan,
    ["game.classic_settlement"] = classic_settlement.plan,
    ["stock.trade"] = stock.trade,
    ["stock.retire"] = stock.retire,
    ["stock.open"] = stock.open,
    ["stock.quote"] = stock.quote, ["stock.market"] = stock.market,
    ["boss.can_attack"] = bosses.can_attack,
    ["boss.probabilities"] = bosses.probabilities,
    ["boss.skill"] = boss_skills.plan,
    ["card.lottery_award"] = lottery.award,
    ["card.rent_transfer"] = rent_transfer.rent,
    ["card.stock_forced_sale"] = forced_sale.liquidate,
    ["card.stock_subscription"] = subscription.transfer,
    ["card.stock_subscription_quantity"] = subscription.quantity,
    ["boss.attack"] = bosses.attack,
    ["boss.chest_select"] = boss_chest.select,
    ["boss.chest_spawn"] = boss_chest.spawn,
    ["mall.purchase_policy"] = mall_purchase.plan,
    ["mall.consumable_policy"] = mall_consumables.plan,
    ["mall.equipment_policy"] = equipment.plan,
    ["mall.equipment_healing"] = equipment_effects.healing,
}
local M = {}
function M.dispatch(event, request)
    local handler = assert(handlers[event], "未注册 Lua 事件：" .. event)
    return handler(request)
end
return M
