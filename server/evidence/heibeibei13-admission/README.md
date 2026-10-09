# 黑贝贝1-3生产入口与长对局验收 · 2026-10-10

## 原阻塞与当前修改

`BS_1_3.emp`原来因对手预建kind16神庙落点未闭合而禁用。此前神庙无效果、既有附身时钟、
自有建造/升级及NPC4/6基础召唤/金额流程已经实现，并有固定落点加密TCP回归
（`evidence/temple-no-effect`）。本轮验证它们在该地图真实长对局中的接续。

先移除测试驱动中“只验资源然后跳过1-3”的分支，保留生产门禁运行：
`build/heibeibei13-before-tests.log`实际失败为`richonline_map_package_runtime_incomplete`。
随后将该地图`runtime_enabled`设为true，`readiness`仍为partial；不改变其他章节入口。

## 实際验证

`three-sessions.jsonl`保存独立三局结果。使用同版本客户端资源、真实生产provider、GameSession/GameService
及加密TCP；独立SQLite，不接触玩家库。每局运行至自然终局，或达到320回合后发送真实0A、收到4006退出。

- 累计544回合、541次移动、142次Boss攻击。
- 50次对手地产、4次神庙落点、17次研究决定、71次地产决定。
- 55次机会事件、28次商店退出、45次NPC拾取。
- 两局自然终局并确认持久化结算/大厅58回调；一局到上限后正常退出。主动退出只登记一次loss，重复清理无重复登记，结算outbox为空。
- 真实资源Boss现金120000/三骰，人类现金20000，两处预建地产；50个资源事件中26个当前规则可处理事件。没有宣称50个事件全部实现。

原始收发明文及落点记录：
`build/scenario-evidence/heibeibei13-admission/BS_1_3.emp.trace.jsonl`。
大厅socket/登录不在此独立游戏驱动范围；全套另有大厅TCP测试。客户端实机玩法尚未UI验收。

共享长局驱动也强化了黑贝贝1-2和1-4：达到测试步数后真实退出、不留未确认结算，并拒绝非预期warning。
没有用合成下一回合或跳过未知事件让测试通过。

## 构建和回归

- 严格全构建：`build/heibeibei13-final-build.log`通过。
- 全套：`build/heibeibei13-final-tests.log`，204/205通过、112.02秒；含三张黑贝贝地图的独立长局和赵灵儿长局。
- 唯一失败为本轮误改的传送测试断言：测试覆盖仍应禁用的`BS_3_1.emp`，并非本轮开放的`BS_1_3.emp`。恢复原断言后，`build/heibeibei13-portal-tests.log`补验1/1通过。205项均已有通过结果，不伪称单次全套全绿。
- `git diff --check -- server`通过。

## 候选与边界

`server/RichOnline.Server.exe` SHA256：
`0DB9D9B8B1029F4DF187510D9F4C0CD7555FCC43E1FBA5F934206378A8A92D68`。
上一候选备份`build-migration-backup/RichOnline.Server.before-heibeibei13.exe`，清单见`candidate.json`。
更新时仅GUI在运行，没有服务实例；GUI下次启动加载新版，不改写旧native-server或旧运行目录。

地图仍为partial。月份到期结算、其他章节和未覆盖卡片/模式继续作为goal工作，不能从三局通过推断完整游戏支持。
