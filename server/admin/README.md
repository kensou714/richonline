# RichOnline .NET 管理器

此目录构建 `RichOnline.Admin.exe`，面向 .NET 8 Windows x64 WinForms。
独立 EXE 使用标准库和 Windows 控件，不依赖 Python、SQLite GUI 库或上游源代码。
C++ 服务端是数据库唯一写入者。管理器只调用 [CONTROL-PROTOCOL.md](../CONTROL-PROTOCOL.md) 定义的当前用户命名管道。

## 当前目录启动

双击 `server/RichOnline.Admin.exe`，点击“启动服务端”。客户端根目录的
`RichOnline.Admin.exe` 也是同一管理器的兼容入口。两者都使用当前
`server/RichOnline.Server.exe` 和 `server/data`，保留启动、停止、账号、设置、日志、备份及客户端启动功能。
管理器关闭会停止它启动的服务。数据目录互斥锁防止两个入口同时运行同一数据库。

路径优先级为命令行、EXE 旁的 `RichOnline.Admin.launch.json`、目录默认值；
配置相对路径以 EXE 所在目录为基准。在 `server` 下能自动识别同目录服务端。
`gameReady:false` 表示完整协议尚未实现，不等于大厅或已开放 BOSS 地图无法连接。
大厅、HTTP、黑名单、游戏端口就绪分别显示。

## 构建和发布

在当前项目根目录使用 Windows .NET SDK 构建并安装自包含单文件：

```powershell
./server/tools/Build-Admin.ps1 -InstallClientEntry
```

省略 `-InstallClientEntry` 只更新 `server` 下的入口。已有入口先备份到
`server/build-migration-backup/admin-*`；普通重建保留已有 server 旁配置。
显式安装根目录入口会将其启动配置指向当前 server/data。底层发布命令为：

```powershell
dotnet publish server/admin/RichOnline.Admin.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o server/admin/publish
```

`server/admin/publish/RichOnline.Admin.exe` 是 Windows x64 单文件；安装脚本会复制到正确位置。

自包含发布不要求使用者安装 .NET；framework-dependent 构建则要求 .NET 8 Desktop Runtime。
构建缓存与临时文件可放 F 盘，避免占满 C 盘。
服务端候选仍由服务端构建/验收流程管理，GUI 构建不会覆盖 `RichOnline.Server.exe`。
首次使用前需配置游戏 runtime；空数据目录只有管理接口。已有库迁移使用以下显式工具：

```powershell
./server/tools/Initialize-LocalGuiData.ps1 -SourceDataDirectory 'F:/大富翁online/local-server/runtime/native-boss-live-20261009'
```

只接受尚不存在的目标目录，默认 `server/data`。通过服务端只读 SQLite backup 导入账号及已提交 WAL，
不改写源数据库，不重置账号或密码；使用当前已验证的三频道 gameplay bootstrap，校验客户端哈希并重定位资源路径。
迁移记录在 `server/data/gui-migration.json`。该命令不是每次启动的必需步骤，不要重复迁移覆盖已有账号。

开发启动可明确选路径；客户端启动要求已验证的 KPD 配置和区域编号：

```powershell
server/RichOnline.Admin.exe --server F:/大富翁online/Richonline/server/RichOnline.Server.exe --data-dir F:/大富翁online/Richonline/server/data --client F:/大富翁online/Richonline/RnClient.exe --client-config F:/大富翁online/Richonline/local-server/fixtures/local.kpd
```

## 管理功能

- 服务：启动、停止、自有 PID 与实例核对；单独显示 gameReady，管理就绪不代表游戏可玩。
- 客户端版本：显式选择 Richonline/Big5 或 Original/GBK，并核验服务端实际profile。无标记迁移库采用所选编码必须明确勾选，默认关闭；只登记来源，不转换或重置旧密码。大厅/HTTP/黑名单监听状态分别展示，监听正常不代表客户端已经验证可用。
- 账号：分页读取、当前页筛选、创建、公共字段编辑；保存带原始快照和原因，余额支持小数。
- 设置：完整 JSON 编辑、revision 比较保存；冲突保留输入并显示错误。
- 日志：异步接收真实 stdout/stderr，每行和可见总量有界；暂停展示、级别筛选、复制、打开日志目录。
- 日志洪峰验证：`RichOnline.Admin.exe --log-self-test OUTPUT_JSON` 在不启动服务或显示窗口的隔离控件实例上验证60001条日志、每批500条、队列/可见2000条与最新错误保留；它不证明实际UI帧率或交互体验。
- 备份：请求服务端 SQLite 一致性在线备份，显示服务实际返回路径。

GUI关闭会停止自己的服务；Job Object 在管理器异常退出时关闭所拥有服务。
客户端启动不隐式重启服务、不登录账号，也不按进程名结束其他程序。
服务页的“结束客户端进程”按配置的RnClient.exe完整路径核实运行进程：先请求正常关闭，3秒后仍未退出则只强制结束该进程，最多再等5秒。它不要求服务端在线，不结束服务端或其他路径的同名客户端；状态和日志显示关闭、强制结束、失败、未运行等结果。
客户端KPD参数必须无引号。含空格、非ASCII或过长路径时，管理器将配置原始字节复制到客户端目录下自有 `richonline-admin-launch/GUID/local.kpd` 后以短ASCII相对路径传入；不覆盖原配置。为允许客户端后续读取，这些自有副本保留在磁盘。
账号密码仅在创建请求中发送，不出现在日志或账号列表。

## 真实控制接口自测

`--gui-self-test OUTPUT_DIR` 使用真实 WinForms 消息循环和按钮 PerformClick，
验证两个目录默认路径、旁配置/参数优先级、启动与 PID 就绪核对、四类监听、账号/设置读取、停止、重启及关闭窗口清理。
它使用当前启动配置和账号库但不编辑账号，需要端口空闲且至少存在一个账号。
结果是 `gui-result.json` 与 `service-page.png`（控件绘制，不是操作系统截图）；不会登录游戏或证明真实客户端玩法已验收。

```powershell
RichOnline.Admin.exe --self-test SERVER_EXE EMPTY_TEST_DATA_DIR [richonline|original]
```

只接受空测试目录，创建隔离测试账号，不接触现有账号。结果写入管理器 EXE 所在目录的 `control-test-result.json`（不在测试数据目录）。完成多次测试时应分别保存结果；进程退出码 0 表示接口验收通过。
覆盖就绪 PID、管理/游戏状态分离、账号创建与小数余额、过期编辑拒绝、配置版本冲突、在线备份及停止。
此自测是后端接口证据，不是原生 GUI 视觉验收，也不证明游戏协议可玩。

`--render-diagnostics OUTPUT_DIR` 从实际 WinForms 控件绘制五个页面在 1120×780 和 900×640 两种窗口尺寸的 PNG 与控件几何信息。它用于布局诊断，明确不是操作系统截图，不能替代真人/Computer Use 交互验收。
