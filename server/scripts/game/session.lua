-- 对局业务总入口：按操作号定位独立卡牌模块，其余动作交给既有状态机兼容接口。
-- game.snapshot 读取本局权威状态；本模块的变量只属于当前对局。
-- 尚未调用原生/数据库且未提交的卡牌脚本出错时，宿主发送 400B 恢复掷骰控件并保留原状态。
-- 原生兼容调用可能已产生副作用，此后报错不能自动重试，仍按连接错误处理。
local cards = require("cards.registry")
local M = {}
function M.action(request)
    local card = cards.by_opcode[request.opcode]
    if card then return card.use(request) end
    return core.call("game.native")
end
return M
