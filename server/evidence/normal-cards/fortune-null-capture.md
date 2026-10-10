# 请神卡召福神：随机赠卡回调空指针（2026-10-10）

## 日志与源码定位

用户报告使用请神卡掉线。`data/logs/native-14508.jsonl:353` 最后一条业务日志为2026-10-10T12:00:17.711Z收到opcode112、8字节；没有随后奖励选择或响应日志。Windows Application事件1000在同一秒记录 `RichOnline.Server.exe` 异常0xc0000005、偏移0x1de77f、PID0x38ac（14508）。因此存在服务进程崩溃，不能把它当作普通业务拒绝。

`boss_session.cpp` 先执行 `rules.cards=std::move(cards)`，随后福神随机赠卡回调仍以 `[cards,...]` 捕获原局部shared_ptr。该指针已为空，调用 `prepare_random_reward` 会解引用空指针。四个福神来源共享此回调。没有崩溃转储，未将故障偏移映射到机器指令；日志不包含实际选中神明，源码确认该福神路径必然存在缺陷。

## 客户端复核与修复

live IDA实例c57d1bd2171b复核RnClient.exe：66EB40处理40C0，读取+6地面位置及+8目标角色；福神case3附身，本人路径设置83834等待后续。65F0C0处理4023，从+4/+6分别读取WORD卡号并以数量1插入，83834分支恢复用卡操作。原始反编译保存在 `fortune-null-capture-client.json`。

将回调捕获改为 `[cards=rules.cards,...]`，持有会话的有效背包对象，保持原先两次顺序随机抽卡、消费后背包和4023响应逻辑。不改卡池、奖励数量或附身续接。

## 编译与安装

后续只读观察用户自行运行的 `native-45308.jsonl:1147`：福神卡131已抽到1038/1041，发出40D3和4023，随后继续收到遥控骰子103及移动请求。2231行请神112返回40C0和4024（衰神分支），随后继续正常行动。这证明本次运行中的福神回调及请神非福神分支已返回，不把这条请神记录误称为请来福神的验证；未由代理启动测试。

`cmake --build server/build --target RichOnline.Server -j 4` 和 `git diff --check -- server` 通过。没有新增或运行测试，没有启动服务/游戏。确认无服务进程后备份并覆盖GUI使用的EXE，安装版和编译版SHA256一致：D859ED0429B93D2ED608E5DC916CECC40A7A85F3E920B68FE446B0E057403B4B。备份清单位于 `build-migration-backup/fortune-null-capture-3477e121073b488d906326a19f61b38d/`。游戏验证由用户完成。
