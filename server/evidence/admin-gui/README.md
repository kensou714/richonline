# GUI 迁移验证 · 2026-10-10

旧 GUI 源码在 `F:/大富翁online/admin`，客户端根目录的启动配置仍选择旧目录中的
`RichOnline.Server.channels.exe`。当前源码/程序统一使用 `server/admin`、
`server/RichOnline.Admin.exe`、`server/RichOnline.Server.exe` 和 `server/data`。
客户端根目录原 GUI 入口也已更新。

## 已验证

- 自包含 .NET 8 Windows x64 单文件发布成功，项目启用 TreatWarningsAsErrors。
- server 入口和客户端根入口都执行真实 WinForms 消息循环；按钮 PerformClick 启动当前候选，
  通过 stdout 公告及命名管道核对 PID/实例/profile，读取账号和设置，停止、重启并随关闭窗口停止服务。
- `gui-result.json`：20 个检查通过；大厅18600、HTTP18680、黑名单18604、游戏18602均监听。
  intro18605、inquiry18606也报告就绪；完整协议覆盖仍为 false。
- `control-test-result.json`：在独立空测试库通过9项控制接口回归；没有用迁入的账号库做写入自测。
- `database-comparison.json`：旧数据库通过 SQLite 只读备份迁移（包含已提交 WAL），26个账号、15张原有表逐行一致，完整性检查通过。报告不包含密码或账号明细。
- `candidate.json`：安装后的 GUI、服务端及客户端哈希和备份位置。

初次 GUI 迁移没有发布未完成的投票接入；当时 server EXE 是全套204/204验收的候选
`793F75F7F37961B43D6F995A677C28CE32321582A8ACE74BAA32E9641CBDF427`。
没有覆盖旧运行目录程序或数据库。

## 本机详细证据

- `server/build/admin-migration-build.log`
- `server/build/admin-gui-evidence/gui-result.json`：server入口
- `server/build/admin-gui-final-evidence/gui-result.json`：根目录兼容入口
- `server/build/admin-gui-final-evidence/service-page.png`：实际控件 DrawToBitmap，非操作系统截图
- `server/data/gui-migration.json`：运行数据迁移记录
- `server/build-migration-backup/admin-d1e4e150eb6a4df094714fad00828769`：迁移前原GUI与启动配置

可复现命令见 [GUI说明](../../admin/README.md)。自动窗体回归证明 GUI 与服务端连接及生命周期，
不等于用户鼠标交互或真实游戏客户端玩法验收。

## 当前候选复验

- 当前两个 GUI 入口 SHA256 相同：`0998364459F9A9032F3E8CF3A4A94E2C9C5EB59D37F94F5389DD3EEAA55EA1C1`。
- 当前 GUI 启动的服务端 SHA256：`0DB9D9B8B1029F4DF187510D9F4C0CD7555FCC43E1FBA5F934206378A8A92D68`，包括后续大厅投票和黑贝贝1-3增量。
- server 入口：`build/gui-verification-20261010-bec56811266840a99071baa53cb15c59/gui-result.json`；根目录入口：`build/gui-root-verification-20261010-cda576438149486b8ef9970d91a605b6/gui-result.json`。两者 `ok:true`，26账号可读取，启动、停止、同库重启和关闭窗口清理全部通过。
- 根目录入口实际服务 PID 42816，实例 `42816-331184339582600`，数据目录为当前 `server/data`；全部六类监听报告就绪。自测结束后没有遗留服务子进程。
- 最新完整服务端回归 `build/heibeibei13-confirmed-tests.log` 为204/205通过、199.28秒。唯一失败为赵灵儿长局calendar35、Boss落点165的 `richonline_boss_landing_unsupported`；同局trace显示该地产198此前已归Boss且神庙升到5级。原因尚未确认，不能用早期全绿或单项重试替代该失败记录。GUI可用与此玩法回归分别记录。
