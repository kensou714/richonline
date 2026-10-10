-- 数据库桥接：只允许服务器脚本调用，客户端不能传入 SQL 作为命令执行。
-- batch 在原生数据库锁内执行一个事务；callback 在提交/回滚后、当前 Lua VM 内调用。
-- 这是真实的同步完成回调，不会伪装成后台异步；回调里不要重复执行已经成功的扣款。
local M = {}
function M.batch(statements, callback)
    local ok, result = pcall(core.call, "db.batch", { statements = statements })
    local event = { ok = ok, result = ok and result or core.null, error = ok and core.null or result }
    if callback then callback(event) end
    if not ok then return nil, result end
    return result
end
function M.query(sql, params, callback)
    return M.batch({ { sql = sql, params = params or core.array() } }, callback)
end
return M
