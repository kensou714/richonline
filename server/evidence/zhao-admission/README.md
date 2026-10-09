# 竞技频道赵灵儿地图开局验收

地图：`V_BS_1_1.emp`，特殊分类 `2`，竞技频道 `2`。

## 修复前证据

现有 `richnet_richonline_zhao_scenarios_tests.exe` 在真实资源和隔离 SQLite 上调用 runtime provider，捕获 `richonline_map_package_runtime_incomplete`。2026-10-09 的运行日志是 `server/build/zhao-before.log`，退出码 0 表示原测试确实断言了拒绝，而不是地图能够游戏。最后一条输出：

```json
{"event":"resource_verified_runtime_gated","map":"V_BS_1_1.emp","reason":"encrypted_multiturn_opponent_property_landing_unsupported"}
```

`src/maps/zhao_linger/v_bs_1_1.cpp` 的 `runtime_enabled=false` 经 `make_richonline_boss_session` 的 package gate 拒绝，房间资源本身已加载成功。旧门禁原因是独立长局曾遇到对手特殊地产未闭合；当前共享地产实现已有独立 TCP 断言，仍需本地图全局验证才能解除门禁。

## 验收边界

`tests/richonline_zhao_scenarios_tests.cpp` 保留资源、经济、Boss 身份、技能、传送门、地图独立事件池检查，增加实际 provider admission 与三场独立加密 GameService TCP 长对局。每局只发送已支持的客户端决定；未识别停顿直接失败，不伪造回合继续。

测试要求三局均能持续推进，合计至少 40 个回合、Boss 攻击、初始控制骰卡、至少三次选骰支付以及至少一次对手地产落点。每局最多跑 320 个回合。如果途中自然破产，验结算 outbox 清空以及显示期结束后的大厅 58 checkpoint；如果仍未破产，则通过真实加密 C2S `0A 00` 主动退出，验 `4006` 回复、持久化 loss 恰好一次以及无待交付 outbox。主动退出不产生 `401B` 或大厅 `58`，这与 terminal coordinator 契约一致。大厅 58 在本 harness 中为串行生命周期回调，登录和大厅 socket 不在这个 GameService 测试中。

测试使用隔离临时数据库，不修改正式数据。未进行客户端 UI 操作，不声称用户正在运行的旧部署已更新。

## 修复后结果

升级后的 owner test 在门禁仍为 false 时先运行，`server/build/zhao-red-tests.log`：

```text
FAIL richonline_map_package_runtime_incomplete
0% tests passed, 1 tests failed out of 1
Total Test time (real) =   0.10 sec
```

只把本地图 `runtime_enabled` 改为 true 后的首次 320 回合候选运行能够一直推进，有 320 条 `4010`、没有 `400B` 或 `401B`，但未自然破产，原“320 回合必终局”验收在 `server/build/zhao-candidate-tests.log` 失败。trace 同时显示人类 41 次地产落点，其中含对手 hotel153/kind13 与普通219/kind11。固定回合内必然破产不是协议契约，已改为上述退出契约，避免随机经济进程导致不稳定测试。

`readiness` 保持 partial，其他地图门禁不变。

修复六/七级建筑校验后，`server/build/zhao-level-green-tests.log` 的地图加密长局和 combat session 固定输入回归均通过：

```text
100% tests passed, 0 tests failed out of 2
Total Test time (real) = 48.79 sec
```

该次地图测试 stdout (`Testing/Temporary/LastTest.log`，后续全套 CTest 会覆盖) 的 `map_pass` 汇总如下：

| 观察项 | 实际值 |
| --- | ---: |
| 场次 | 3 |
| 总回合 / 移动 | 723 / 720 |
| Boss 攻击 | 204 |
| 对手地产落点 | 37 |
| 地产决定 / 研究决定 | 67 / 9 |
| 初始控制骰卡 / 选骰支付 | 3 / 9 |
| 自然破产终局并确认大厅 58 | 1 |
| 主动退出并收到 4006 | 2 |
| 机会事件 / 商店退出 | 106 / 23 |

第 0 局第 83 回合自然终局；随后同一账号、同一 runtime 的第 1/2 局各跑满 320 回合，并正常退出。每局结算 outbox 清空，主动退出在 socket 关闭和再次调用 disconnected 后 loss 仍只增加一次。没有未预期 warning。实际资源 `game_months=3` / `wait_seconds=10`，当前 runtime 不实现按月份比较资产的到期终局，本验收不声称覆盖该功能。

这证明 provider 开局、地图通信续接、自然终局和后续再次开局均可运行；`client_ui_verified=false`、`live_data_touched=false`。没有在客户端 UI 点击竞技房间，也没有部署到用户正在运行的服务。

## 长局发现的六级建筑冲突

第一次按真实退出契约运行的候选在第 208 回合断开，`server/build/zhao-verified-tests.log` 记录：

```text
game_connection_closed reason=richonline_combat_session_building_invalid
FAIL tcp_receive_closed_or_timed_out
```

此处不是退出，也不是网络偶发超时。加密 trace 中的最后地产前态和请求：

```json
{"actor_slot":0,"building_kind":11,"building_level":5,"owner":0,"pending_opcode":56,"property_ref":219}
{"direction":"c2s","opcode":56,"plain":[56,0,208,0,1,165]}
{"direction":"s2c","opcode":16446,"plain":[62,64,1,0,1]}
{"direction":"c2s","opcode":57,"plain":[57,0,208,0,1,165]}
```

赵灵儿资源允许 scenario caps `{6,6,6,6,0,6,0,0,0,0}`，而原 combat session 校验将任何 `building.level>5` 视为损坏。地产升级从 5 到 6 后，下一回合 combat snapshot 因该硬编码上限关闭连接。此失败必须由 combat owner 的边界回归和后续长局验证修复，不能降低本测试地产升级覆盖来回避。

对应修复保留客户端 3-bit 建筑等级的 `0..7` 边界，在 combat snapshot、adapter 结果和 blast 等级验证三处统一；六/七级建筑的导弹不降级、两种核弹逐级减一，以及八级拒绝，由 `richonline_combat_session_tests.cpp` 独立固定输入回归覆盖。原地图初始建筑资源加载仍维持已有约束，本图初始资源无需放宽。

对手预建寺庙的确定性补充回归位于 `richonline_owned_property_tcp_tests.cpp`，本图 `V_BS_1_1.emp` / category2 / road165：双方访客、附身状态、友好关系和召唤 aura 均走真实 TCP；本长局验证地图组合后的自然通信续接，不依赖随机路线恰好在寺庙被摧毁前再次到访。
