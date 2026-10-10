-- 原料卡（资源编号 519）。本文件是该卡的独立业务入口。
-- 本卡没有主动 TCP 使用请求；保留独立资源定义，供被动效果消费者查询。
-- 当前复杂效果使用原生兼容事务，库存、状态与响应须由同一次操作共同提交。
-- reward_enabled 只控制随机赠卡；还必须通过资源 enable、CARD 类型及地图允许列表。
local M = { id = 519, name = "原料卡", opcode = nil, reward_enabled = false, implementation = "native_compatibility" }
return M
