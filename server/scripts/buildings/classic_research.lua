-- 经典研究所：只生成登记和扫描意图，C++持有权威回合、产权及局内手牌。
local M = {}
local rewards = {1062, 1038, 1044, 1042, 1063}
function M.choose(request)
    local choice = request.requested
    assert(choice == -1 or (choice >= 1 and choice <= 5 and choice <= request.level), "研究选择无效")
    if request.timed_out or request.free_slot == -1 then choice = -1 end
    return {
        choice = choice, slot = choice == -1 and -1 or request.free_slot,
        remaining = choice == -1 and 0 or choice + 1,
        message = string.pack("<I2I2b", 0x4026, request.game_id, choice),
    }
end
function M.scan(request)
    local changes = core.array()
    for _, job in ipairs(request.jobs) do
        local cancelled = job.kind ~= 2 or job.level < job.choice or job.owner ~= request.actor
        local remaining = cancelled and 0 or ((job.remaining - 1) & 0xFF)
        changes[#changes + 1] = {
            slot = job.slot, remaining = remaining, cancelled = cancelled,
            card = not cancelled and remaining == 0 and rewards[job.choice] or -1,
        }
    end
    return changes
end
return M
