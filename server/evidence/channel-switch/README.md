# 从房间列表切换频道闪退（2026-10-09）

## 现场证据

- 原运行日志：`F:/大富翁online/local-server/runtime/native-boss-live-20261009/logs/native-17772.jsonl`。
- 14:19:20.382Z、14:20:06.490Z 均收到 C2S8、4字节payload，随后 `lobby_authenticated_request_rejected: handler_not_implemented`、`lobby_connection_closed reason=lobby_authenticated_request_unsupported`。第二次之前 C2S6 已完成14/57，正是用户报告的房间列表切频道路径。
- 对应客户端转储 `CoreDump/1009221920.dmp`、`CoreDump/1009222006.dmp`（本地UTC+8时间）均为 `EIP=0089fd01 EDX=dddddddd`，`call dword ptr [edx]`。后者的只读CDB输出保存在 `crash-1009222006.txt`。
- NEW89FB00大厅对象析构最后释放`this+32`时访问已释放的子对象；栈经82D2D0、87DD40、855600。这是连接关闭后的客户端析构故障，不能归因于“16格式错误”，因为现场根本没有发送16。
- 此次检查时旧运行日志已在14:20:11Z明确stop，本机没有对应服务进程。当前源码包含C2S8清理与空payload S2C16，现场旧二进制缺少该流程；源码修复不等于运行版本已更新。
- 旧运行EXE SHA256为`A3CE3E3798E06BD44850F6ADEF67BFA3FFF193E183F023BFB378BA405C0133FD`；当时server候选为`CD342C4680BD6F5D10F5604A85DAA9D5521884DE5684ACFD76DA4203D70F9B06`。本轮加入赵灵儿修复后还会产生新候选，以`build-migration-backup/zhao-channel-candidate.json`为准。

## 回归

`tests/richonline_room_runtime_tests.cpp` 在真实LobbyRuntime TCP上追加：建房→退房14/57→请求8→空16→同一已认证连接在竞技2/频道0间往返四次→返回0，不重新登录、不重新选角色；校验房间快照隔离和旧/新频道55/7在线缓存。

`tests/richonline_lobby_membership_session_tests.cpp` 原有加密会话测试另覆盖房主离开转移、正在游戏拒绝、不丢认证、重复离开拒绝及人数更新。两项当前通过，见`build/channel-switch-tests.log`（2/2，3.48秒）。原服务拒绝路径已有两份现场失败证据，没有为了复现重新中断用户游戏。

边界：这是服务端触发条件修复及真实TCP回归。未在真实客户端UI重新点击验收；客户端异常断线时的析构本身仍需客户端维护会话独立修复。最终发布必须使用当前server候选，不能继续运行原旧EXE。
