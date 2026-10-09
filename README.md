# RichOnline

RichOnline 是大富翁 Online 的开发资料与原生服务端源码归档。本仓库用于协作、源码审阅和可复现构建，当前公开访问：<https://github.com/kensou714/richonline>。

## 仓库范围

- `docs/`：开发约定、服务端资料、客户端研究资料、协议分析和验证证据。
- `server/`：C++20 服务端源码、头文件、CMake 构建配置、测试、工具、Lua 规则及已记录许可的第三方源码。

客户端原有资源、商业客户端程序、运行时账号数据库、日志和本地构建产物不随仓库发布。服务端源码中的部分测试需要本地客户端资源或历史分析输入；缺少这些输入时，不能把测试标记为通过。

## 当前状态

服务端已包含管理管道、SQLite 账户与设置存储、协议编解码、大厅、可配置游戏监听器和多组游戏模块。`gameListenerReady` 表示游戏监听状态；`gameReady` 当前仍为 `false`，全部地图、完整 BOSS 玩法和真实客户端兼容性尚未宣称完成。请先阅读 [支持边界与协作回归](docs/服务端开发资料/07_支持边界与协作回归.txt)。

2026-10-09 初次归档时，已在 Windows / LLVM-MinGW clang 22.1.3 环境完成 CMake 配置和 `RichOnline.Server` 目标编译。本次记录不代表完整 CTest、真实客户端验收或线上部署已完成。

## 阅读入口

| 主题 | 文档 |
| --- | --- |
| 项目背景与资料导航 | [从这里开始](docs/00_从这里开始.txt) |
| 源码导入与路径映射 | [Git 仓库与源码快照](docs/04_Git仓库与源码快照.txt) |
| 服务端架构、构建与运行 | [服务端资料索引](docs/服务端开发资料/00_阅读索引.txt) |
| 客户端资源与维护研究 | [客户端资料索引](docs/客户端开发资料/00_阅读索引.txt) |
| 协议与逆向证据 | [逆向资料索引](docs/逆向资料/00_阅读索引.txt) |

源码从原工作区的 `../native-server` 导入本仓库 `server/`。历史文档保留的 `../native-server` 路径应按此映射阅读；`../admin`、`../local-server` 和外部 `protocol-analysis` 未随本次归档导入。原开发目录后续变更不会自动同步到本仓库。

## 构建

正式服务端及多数集成测试需要 Windows。以下命令使用 CMake 3.24 或更高版本、LLVM-MinGW 的 `clang` / `clang++` 和 Ninja，执行前应将工具加入 `PATH`。首次配置会通过 CMake FetchContent 下载 Lua 5.4.8，并校验固定 SHA-256。服务端运行不需要 Python；历史 Python 对比脚本有另外的外部输入要求。

```powershell
git clone https://github.com/kensou714/richonline.git
cd richonline
```

在仓库根目录执行：

```powershell
cmake -S server -B server/build -G Ninja `
  -DCMAKE_C_COMPILER=clang `
  -DCMAKE_CXX_COMPILER=clang++ `
  -DCMAKE_BUILD_TYPE=Release `
  -DBUILD_TESTING=ON
cmake --build server/build --parallel 4
ctest --test-dir server/build --output-on-failure
```

如果测试需要客户端资源，可在配置时指定本机资源目录：

```powershell
cmake -S server -B server/build -G Ninja `
  -DRICHONLINE_CLIENT_DIR="D:\path\to\Richonline-client"
```

`RICHONLINE_CLIENT_DIR` 默认指向仓库根目录。仓库不提供客户端资源，因此依赖资源的测试需要单独准备合法输入。

## 隔离运行

服务端使用独立数据目录，避免误操作线上或历史数据库：

```powershell
server\build\RichOnline.Server.exe `
  --data-dir D:\richonline-data `
  --pipe richonline-admin `
  --client-profile richonline
```

`D:\richonline-data` 为示例，请替换为独立数据目录的绝对路径。未提供大厅启动配置 `lobby-bootstrap.json` 时，只启动管理能力；开放大厅和游戏链路还需要准备资源路径、端口与对应配置。

运行前请阅读 [配置与管理接口](docs/服务端开发资料/03_配置与管理接口.txt) 和 [`server/CONTROL-PROTOCOL.md`](server/CONTROL-PROTOCOL.md)。[`server/README.md`](server/README.md) 保留了服务端历史说明，其中旧目录和阶段性结论需结合当前源码核对。切换部署版本前应保留数据备份、程序哈希和回滚路径。

## 依赖与许可

第三方依赖及来源记录在 [`server/vendor/DEPENDENCIES.md`](server/vendor/DEPENDENCIES.md)、[`server/vendor/lzokay/SOURCE.md`](server/vendor/lzokay/SOURCE.md) 和 [`server/vendor/lzokay/LICENSE`](server/vendor/lzokay/LICENSE)。提交或再分发新增依赖前，请先确认其许可证和来源。仓库中的项目资料不授予客户端资源或第三方逆向材料的额外再分发权。

## 协作

提交代码时请说明改动范围、构建命令、测试结果、未验证场景和部署状态。密码、令牌、私钥、真实账号数据和完整日志不得提交。详细约定见 [`docs/01_协作与维护约定.txt`](docs/01_协作与维护约定.txt)。
