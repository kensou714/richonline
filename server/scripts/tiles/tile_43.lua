-- 静态格类型 43 的独立落点入口；type 是 EMP 静态类型，不是道路位置编号。
-- 此事件在移动/NPC/传送阶段处理后进入，核心已提供 actor、position 与 map。
-- tile.native 必须恰好调用一次：它拥有库存/资金事务以及后续交互阶段，不能伪造完成。
-- 自定义奖励应通过核心事务返回协议响应，不能只发客户端提示而漏改权威状态。
local M = { type = 43, implementation = "native_compatibility" }
function M.land(request) return core.call("tile.native") end
return M
