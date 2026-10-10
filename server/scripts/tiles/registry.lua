-- 道具格业务分发。未知类型沿用原生校验，不能静默当普通道路处理。
local modules = {
    [5] = require("tiles.tile_5"),
    [6] = require("tiles.tile_6"),
    [7] = require("tiles.tile_7"),
    [8] = require("tiles.tile_8"),
    [10] = require("tiles.tile_10"),
    [12] = require("tiles.tile_12"),
    [28] = require("tiles.tile_28"),
    [33] = require("tiles.tile_33"),
    [34] = require("tiles.tile_34"),
    [35] = require("tiles.tile_35"),
    [36] = require("tiles.tile_36"),
    [41] = require("tiles.tile_41"),
    [42] = require("tiles.tile_42"),
    [43] = require("tiles.tile_43"),
    [51] = require("tiles.tile_51"),
    [53] = require("tiles.tile_53"),
    [54] = require("tiles.tile_54"),
    [57] = require("tiles.tile_57"),
    [58] = require("tiles.tile_58"),
    [61] = require("tiles.tile_61"),
    [68] = require("tiles.tile_68"),
    [69] = require("tiles.tile_69"),
    [70] = require("tiles.tile_70"),
}
local M = {}
function M.land(request)
    local tile = modules[request.type]
    if tile then return tile.land(request) end
    return core.call("tile.native")
end
return M
