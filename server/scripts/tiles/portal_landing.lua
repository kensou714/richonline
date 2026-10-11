-- 三类传送格共用准备接口：核心负责地图配对、受控状态、候选池和一次随机抽样。
-- 本模块只编排目标和报文，位置与出口地雷在宿主验证返回后才提交。
local protocol = require("core.protocol")
local M = {}
function M.land(request)
    local supported = false
    for _, capability in ipairs(core.capabilities()) do
        if capability == "tile.portal.prepare" then supported = true end
    end
    if not supported or not request.portal_landing_available then return core.call("tile.native") end
    local plan = core.call("tile.portal.prepare")
    local messages = {protocol.inner(0x4013, request.game_id, string.pack("<i2", request.position))}
    local destination = plan.destination
    if plan.kind == "random" then
        assert(request.type == 58 and #plan.destinations > 0, "乱传格候选无效")
        local index = core.call("tile.portal.random", {bound = #plan.destinations})
        assert(math.type(index) == "integer" and index >= 0 and index < #plan.destinations, "传送随机索引越界")
        destination = plan.destinations[index + 1]
        messages[#messages + 1] = protocol.inner(0x4209, request.game_id, string.pack("<i2", destination))
    elseif plan.kind == "paired" then
        -- 28/61收到入口4013后自行传送；不能再发4209或出口4013。
        assert(request.type == 28 or request.type == 61, "成对传送类型无效")
        assert(destination ~= request.position, "成对传送终点无效")
    else
        assert(plan.kind == "skip" and destination == request.position, "传送跳过状态无效")
    end
    return {destination = destination, messages = messages}
end
return M
