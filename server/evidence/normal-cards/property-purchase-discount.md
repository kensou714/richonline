# 普通购地与购地卡统一价格（2026-10-10）

## 来源与故障范围

最新读取 `data/logs/native-29592.jsonl` 没有新增未实现落点/卡牌拒绝，仍有已记录的商店点券不足。本次由源码审计发现普通购地固定使用原价，属于潜在现金不同步，不是对该日志点券故障的另一种解释。

保存的客户端证据：

- `docs/逆向资料/专题/回合继续与落点调度/阶段2_01_入口与分支树.txt:62`：mode3/4无主地产使用7CF5E0调整价格，现金严格大于调整后的价格才询问购地。
- `阶段2_02_建筑选择与本地事件.txt:48`：7CF5E0从指定角色取P+152，以有符号正数判断折扣并算术右移一位。
- `docs/逆向资料/专题/回合等待与自动选择/证据/pending_functions.json` 的65E8C0（4020消费者）：接受后取地产价格，经608EF7调整，再登记费用和扣当前角色现金。当前BOSS地产均为type12，不包含该回复的专用地产价格旁路。
- 人类profile的slot2映射见 `purchase1031.md`；BOSS的slot2来自 `RichonlineStageBoss::equipment[2]` / `bossLand`，与既有 `RichonlineCombatModifierResources::boss_equipment` 映射一致。

IDA-MCP本轮再次报告实例5c7b48b1123e超时，故使用以上保存的原始反编译资料，未宣称在线重新反编译。

## 修改

`RichonlineBossProperty::purchase_price` 统一查询地产原价与角色折扣。普通落点的购地询问、玩家接受后的扣款、合成BOSS自动购地、购地卡96均使用该报价。保留现金严格大于价格，半价奇数向下取整；不修改地产原始价格，不给旧地主加钱。

人类会话从同一份开局profile配置折扣，资料未知时不猜全价。BOSS从实际关卡装备初始化；单独构造的无profile地产组件仍以裸装人类为默认值。装备判断保持signed DWORD>0，不能仅使用非零判断。

## 构建与安装状态

`cmake --build server/build --target RichOnline.Server -j 4` 成功，`git diff --check -- server` 通过。未新增/运行测试，未启动服务；游戏验证由用户完成。

候选 `build/RichOnline.Server.exe` SHA256：`B5088C29969DE5DBEBB626439EB7B0DF3956893764F741F7E104AF43E9C3523A`。该候选也包含之前尚未安装的重阳节99点券、商店传输余量和换地/换屋条件修复。最后复查GUI服务PID29592仍运行，没有覆盖运行中的 `RichOnline.Server.exe`。
