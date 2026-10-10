# 服务端 goal 接续与构建修复（2026-10-11）

## 接续范围

从会话 `01a12060-5ab4-7942-99ed-814bb4a10bce` 接续服务端通信协议与 C++ 核心/Lua 业务迁移目标。工作目录仅为 `server`，不改旧 `native-server`。按用户既有要求只编写代码和编译，不新增/执行游戏或协议测试，不启动服务。完整协议与 Lua 迁移仍未完成。

## 旧构建为什么没有交付

- 旧 GUI 安装版哈希为 `D50355F4315450B89F92D3FE4A9B030DF26E762BA065AA46444F0E115C4FA96F`，对应商城策略版本；后续移动卡接口修改尚未交付同代 EXE。
- `build/CMakeFiles/richonline_scripts-d06319e.bat` 第 3 行长 8,674 个字符，一次向 `luac -p` 传入全部 Lua 文件，超过 Windows `cmd.exe` 的 8,191 字符命令限制。
- 原会话留下一个停在脚本批处理的构建，以及另一个使用不同 Ninja 版本的构建；后者仍在写 `build`，引发日志重整时 `failed recompaction: Permission denied`。
- 本次将 Lua 语法编译改成逐模块命令并启用 `VERBATIM`，每条命令只包含一个脚本。只有全部模块语法通过后才复制脚本目录，主程序依赖此步骤。
- 本次使用 `build-goal-resume` 独立构建目录，使用现有 Clang 22.1.3/LLVM-MinGW、Ninja 与已有 Lua 5.4.8 源码，关闭测试目标。

## 本次构建包含的遗留修复

- 转向卡、停留卡等共享入口使用 `core.active_target.motion`，对应 C++ `motion.prepare`；梦游自目标恢复掷骰续接。二至五步卡仍保留原生固定步数入口。
- `scripts/game/rewards.lua` 从卡片格、福神、节日共享随机池排除 500–519 商城金豆卡。
- `src/gameplay/shop.cpp` 对未定价卡的出售请求返回已有商店关闭响应，保留库存和点券，不让 `richonline_shop_price_unknown` 传播成对局异常。

## 交付结果

- `cmake --build server/build-goal-resume --target RichOnline.Server -j 4` 退出码 0，主程序链接与全部 148 个 Lua 模块语法编译通过。
- 源码脚本与构建目录脚本数量、逐文件 SHA256 一致；确认无服务进程后更新 GUI 使用的 `server/RichOnline.Server.exe`，与候选程序哈希一致。
- 安装版 SHA256：`6A841B93760F064A02CFCF1C9967853FB48FC903CFF3EF39ECCA194EBB6DC1EA`。
- 配对回执：`build-migration-backup/goal-resume-d8957fc6f50b426e92c7f5185da57c8b/candidate.json`。该目录同时保存新旧 EXE、新旧配套脚本及全部脚本哈希。旧配套脚本取自旧安装版相同哈希的商城版本快照。
- 未启动服务、游戏或测试。这些结果仅代表编译与交付核验，不代表实机验证。
