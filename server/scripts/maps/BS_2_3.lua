-- 地图 BS_2_3.emp 的独立配置/事件模块。
-- 地形与资源仍从 server/config/resources 的 EMP 副本读取，本文件只管理服务端规则。
-- boss 指向独立 BOSS 模块；新增地图还需提供合法 EMP/BossWar 资源及原生资源装载支持。
local M = { name = "BS_2_3.emp", boss = "azhanbo" }
function M.reward_pool(candidates)
    -- 可在这里按地图限制赠卡。cards.registry 还会过滤未开放卡牌。
    return candidates
end
return M
