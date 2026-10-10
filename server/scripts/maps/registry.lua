-- 地图模块注册表。键使用客户端资源文件名，大小写必须与资源完全一致。
local M = {}
M["BS_1_1.emp"] = require("maps.BS_1_1")
M["BS_1_2.emp"] = require("maps.BS_1_2")
M["BS_1_3.emp"] = require("maps.BS_1_3")
M["BS_1_4.emp"] = require("maps.BS_1_4")
M["BS_2_1.emp"] = require("maps.BS_2_1")
M["BS_2_2.emp"] = require("maps.BS_2_2")
M["BS_2_3.emp"] = require("maps.BS_2_3")
M["BS_2_4.emp"] = require("maps.BS_2_4")
M["BS_3_1.emp"] = require("maps.BS_3_1")
M["BS_3_2.emp"] = require("maps.BS_3_2")
M["BS_3_3.emp"] = require("maps.BS_3_3")
M["BS_3_4.emp"] = require("maps.BS_3_4")
M["V_BS_1_1.emp"] = require("maps.V_BS_1_1")
return M
