# 服务端独立资源

服务端运行资源保存在 `config/resources`，不再从客户端安装目录读取。
当前导出含 15 个 Data KPD 和 13 个 BOSS 地图 EMP，共 28 个原始文件；
`runtime-resources.json` 列出必需文件及可选的 `Data/Grant.kpd`。
当前客户端没有 Grant，副本也保持缺失，沿用服务端已实现的默认限制行为。

目录布局：

```text
server/
  RichOnline.Server.exe
  RichOnline.Admin.exe
  data/lobby-bootstrap.json
  config/
    lobby-bootstrap.template.json
    runtime-resources.json
    resources/
      manifest.json
      Data/*.kpd
      Map/*.emp
```

`data/lobby-bootstrap.json` 中历史字段 `richonline_boss_game.client_root`
现为 `../config/resources`，相对于 bootstrap 所在目录解析。
字段名称保留以兼容现有服务端和 GUI，实际含义为资源副本根目录。
模板位于 config 目录，故模板中的同一字段为 `resources`；初始化工具会按目标数据目录重新计算路径。

可整体搬移 server 运行目录，并保留 data、config/resources 和运行程序。
GUI 启动服务不需要 RnClient.exe；“启动客户端”是独立功能，需要另行配置客户端路径。
若 GUI launch 配置显式设置了绝对的服务端/数据目录路径，搬移后也需修改这些路径。

首次导出或准备新版本副本：

```powershell
./server/tools/Export-ServerResources.ps1 -SourceDirectory 'F:/大富翁online/Richonline'
# 已有资源变化时导出新目录，再在停服后调整 bootstrap 路径：
./server/tools/Export-ServerResources.ps1 -SourceDirectory 'F:/客户端目录' -DestinationDirectory 'F:/服务端/server/config/resources-next'
```

工具按清单复制原始字节，逐文件核对 SHA256，再将临时目录移入目标目录。
已存在且相同的副本可以复用；存在差异时拒绝覆盖，以保留手工配置并避免热改加载中的资源。
manifest 记录文件大小、SHA256、缺失的可选文件及来源目录；其中来源目录和可选客户端 EXE 哈希仅用于追溯，运行时不会访问来源。
资源中的经济数值和客户端本地计算必须一致，不能仅改服务端副本就认为客户端显示和结算会自动兼容。

`Initialize-LocalGuiData.ps1` 使用此目录的 bootstrap 模板及资源清单，校验副本后迁移账号库；
无需客户端 EXE，也不依赖 tests 目录。协议配置中的 client_sha256 保留为已有兼容性标识，不用导出时的 EXE 哈希替换。
已有 data 无需重新初始化。本次只修改资源路径，下次服务启动生效，不自动重启服务。
