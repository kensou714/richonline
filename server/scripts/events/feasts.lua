-- 节日奖励策略。slot 是 Feast.kpd 中从 0 开始的节日槽位，不是现实月份。
-- 这些固定点券由客户端本地消息 6062 显示，服务端只同步账本，不重复发奖励包。
-- 圣诞 slot=5 已核对 NEW7BE080/NEW66A970：当前证据仅支持随机赠卡，不能猜测点券数量。
local M = {}
local tickets = { [0] = 111, [6] = 180, [8] = 55, [11] = 99 }
function M.tickets(request) return tickets[request.slot] or 0 end
return M
