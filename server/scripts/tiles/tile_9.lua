-- 银行格9：核心认证道路、日历和账户快照；本模块计算交易并组织4018/402A。
-- 脚本不写账户或等待状态。结果经核心完整复核后，才允许提交余额与续接。
local protocol = require("core.protocol")
local M = {type = 9, implementation = "lua"}

function M.open(request)
    return protocol.inner(0x4018, request.game_id,
        string.pack("<i2BB", request.position, request.passing and 1 or 0, request.padding))
end

function M.transaction(request)
    local action, amount, outcome = 2, 0, "exited"
    local cash, deposit = request.cash, request.deposit
    -- BOSS当前采用不交易策略；超时优先于玩家提交，避免到期后仍扣款。
    if request.synthetic then
        outcome = "synthetic_exit"
    elseif request.timed_out then
        outcome = "timed_out"
    elseif request.action ~= 2 then
        assert(request.action == 0 or request.action == 1, "银行操作无效")
        local source = request.action == 0 and cash or deposit
        local destination = request.action == 0 and deposit or cash
        -- 客户端已把“取全部”换算为正金额；0和负金额不能解释成全额交易。
        if request.amount <= 0 then
            outcome = "rejected_amount"
        elseif request.amount > source then
            outcome = "insufficient_funds"
        elseif request.amount > 2147483647 - destination then
            outcome = "destination_limit"
        else
            action, amount, outcome = request.action, request.amount, "transferred"
            if action == 0 then
                cash, deposit = cash - amount, deposit + amount
            else
                cash, deposit = cash + amount, deposit - amount
            end
        end
    end
    -- 两个保留字节沿用已核实策略，不回显客户端请求中的未赋值字节。
    local message = protocol.inner(0x402a, request.game_id,
        string.pack("<I2BBI4", action, request.padding[1], request.padding[2], amount))
    return {action = action, amount = amount, cash = cash, deposit = deposit, outcome = outcome, message = message}
end

function M.land(request)
    -- 可进入银行的落点和途中暂停由核心单独调用open；受控角色保持原有跳过规则。
    return core.call("tile.native")
end
return M
