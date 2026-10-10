# 神庙6/7级召唤与续接

2026-10-10，当前双角色 mode3 服务端。

## 原因与证据

`build/heibeibei13-confirmed-tests.log` 的赵灵儿长局在Boss神庙落点断开。
临时观测保存在 `build/temple-observed-tests.log`：第二局calendar87、位置166，
无附身的Boss尝试从5级升6级；预检不支持该等级的NPC3召唤。
固定回归 `zhao_boss_temple_five_to_six_continues` 在修复前失败，见
`build/temple6-red-tests.log`；修复后通过，见 `build/temple6-green-tests.log`。

NEW证据使用既有 `own-temple-evidence.json` 的7C6640、7D7160、7D70A0，
输入SHA256为 `cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77`。
MI zao友方/敌方列确定6级为NPC3/2，7级为NPC0/1。
本地6051携带origin2与ground=-1；已有福神、衰神、财穷神规划器保留
temple来源和phase6续接，不能再次运行地产或升级。

## 实现

- 地产通过显式NPC能力数组开放0至3，缺少衰神策略时NPC2仍拒绝。
- 神庙入口不消费地面神明，不重复发送4013，不制造附身网络消息。
  人类福神发送4023、衰神发送4024；Boss不操作人类背包。
- 财穷神人类等待34/超时后返回4022；Boss立即按现有服务端金额策略处理。
  金额与破产沿用共享账本和终局协调器。
- 保存角色自身回合身份及附身时钟，升级决定退休后完成phase6。
  迟到升级/转盘不得重复提交。
- 本节记录最初增量，当时正值神庙强化保留门禁。后续源码已通过 `prepare_temple_change` 写入强化强度，并由 `richonline_possession_combat_terms` 与 NPC 光环消费者处理；不应再把本历史说明当作当前缺失分支。地面NPC4/6仍未开放。

## 回归范围

NPC事务测试覆盖0至3、人类/Boss、消息、奖励/损卡、地面不变、同回合幂等、
到期、错误calendar/actor、重放、失败金额规划、转盘超时与破产。
加密TCP覆盖两张地图5至7级、自有/对手、人类/Boss、升级接受/取消，
以及赵灵儿位置166的Boss5升6固定场景。

TCP夹具曾把目标等级设为6/7但保留黑贝贝Boss5级技能，导致初始化不推进；
已显式设置夹具技能并增加升级进度断言，不修改生产地图技能。
TCP矩阵独立通过，17.09秒；30秒CTest时限保留。
完整回归 `build/temple-high-final-tests.log`：205/205通过、247.90秒。
候选安装与两个GUI入口复验通过，详见 `server/DEVELOPMENT.md`。
以上自动测试不替代真实游戏客户端UI验收。
