# 管理服务真实集成验证

2026-10-09，C++20/LLVM-MinGW 严格警告构建完成，SQLite3.50.4静态链接。

`RichOnline.Server.exe` 目前提供本机管理接口与账号/配置持久化；`gameReady=false` 是真实功能边界，尚未取代大厅与游戏服务。

## Red / Green

管理 GUI 的真实命名管道 self-test 首次在 ready 之后 status 读取 EndOfStreamException。服务 WriteFile 完成后立即 DisconnectNamedPipe，客户端未读取的应答被丢弃。

修复：WriteFile 后以有界 overlapped read 等待客户端关闭（单连接仅一请求/应答），最迟请求deadline5秒取消；客户端读完完整帧并Dispose之后才断开服务器端。没有使用可无限阻塞的 FlushFileBuffers。

复测：`admin/publish/control-test-result.json`，隔离目录 `admin/evidence/control-data-04`，7项PASS：状态PID、创建账号、小数余额CAS、stale拒绝、配置CAS、一致备份、优雅停止。之前失败证据保留在admin/evidence。

## 已执行原生回归

`ctest --test-dir native-server/build-ninja --output-on-failure`：native_storage、native_codec 2/2 PASS。各自包含多组固定字节/密码向量与真实SQLite行为，不代表客户端游戏已可玩。

## 未完成验证

补充纯C++真实进程集成测试 `native_control`：非法JSON、0/65537长度、未知command、半包断开恢复、同data第二进程拒绝、读完应答不关闭连接5秒后恢复、stop应答及exit0均通过。最终CTest3/3 PASS，5.47秒。处理响应已发后的关闭超时现已独立记录，不向同连接补发第二帧。

跨用户ACL负向测试尚未用另一个Windows账号执行；Windows GUI屏幕捕获超时，布局渲染不是实际点击验收。原生客户端登录/频道/BOSS流程尚未接入该C++进程。
