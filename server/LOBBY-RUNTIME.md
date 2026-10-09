# 原生大厅运行范围

`RichOnline.Server.exe` 使用 C++20 / WinSock / SQLite。管理器通过 .NET 命名管道调用管理接口。运行路径不启动 Python。

管理数据目录中存在显式 `lobby-bootstrap.json` 时，主服务启动大厅、HTTP 地址发现和 Black 查询监听；没有该文件时仅启动管理接口。未知构包字节必须由配置提供，并保留来源。测试目录里的合成模板不是生产协议默认值。

`network` 必须明确提供 `bind_host`、`advertised_host`、`lobby_port`、`http_port`、`black_port`。测试允许端口0，由系统分配；HTTP 返回实际大厅端口。频道固定键0，容量来自模板策略。在线数量来自真实已认证连接数，包含尚在频道选择界面的连接，不能等同于房间人数。

状态中的 `lobbyReady`、`httpReady`、`blackReady` 表示监听成功。`gameReady` 仍为 false。监听失败记录 `listener_failed` 与稳定原因，后续 `status` 返回 `listenerFailure`。管理能力与游戏能力分别报告。

关闭时停止并 join 所有本实例线程，再关闭 SQLite。启动失败也通过同一析构路径清理已启动的监听。空闲停止由事件循环检查；发送等待受单次5秒限制，拥塞场景不能用空闲停止耗时估算。

JSONL 日志和标准输出由主服务互斥写入。通信日志保留方向、包类型、长度、连接编号及关闭原因，不记录认证正文。辅助服务记录 service、connection_id、wire_type、request_bytes、response_bytes。

## 本次验证

- 2026-10-09：CMake 严格构建成功，CTest8/8通过。
- `native_lobby_runtime` 以合成配置和隔离 SQLite 完成真实 TCP 登录、HTTP 实际端口/会话数量、连接退出数量回落、重复端口拒绝及所有监听停止。
- 独立 EXE32776：实际 curl 请求HTTP12338成功；真实 .NET 管道返回PID一致的状态、三个监听就绪、gameReady=false；stop应答后正常退出。证据目录 `build-ninja/live-native-probe-20261009/`。
- 新版客户端31092由x86CDB59032从启动时调试；C++37636使用独立数据库副本在18600/18680/18604监听。当前等待人工登录与频道结果；不宣称大厅或BOSS已验证可用。
- 首次调试启动的加引号KPD触发`no file`；IDA622E20证明其参数解析不去引号。改用ASCII相对路径后，窗口标题为RichOnline并正常响应。没有修改客户端二进制或资源。

经济参数的含义、商城、排行、社交、房间和游戏业务尚未完整接入。隔离频道诊断配置对构造初态、忽略填充、空库存及经济实验值逐项标注；这些选择不是官方业务域证明。
