# 遥控骰子与二至五步卡 Lua 迁移（2026-10-11）

## 行为来源

- `src/richonline_controlled_dice.cpp`：操作号 103 的请求为 12 字节，+4 库存槽、+5 主背包、+6 骰点 1–6、+7 不解释的保留字节，+8 DWORD 必须为 0。确认 40B7 只含游戏号、槽位和背包。
- `src/gameplay/cards.cpp` 的 `parse_richonline_fixed_step_card` / `plan_richonline_fixed_step_card`：137–140 请求为 6 字节，对应卡号 1080–1083、步数 2–5、确认 40D9–40DC。没有目标角色字段。
- `src/gameplay/boss_turns.cpp` 原生分支在准备扣卡后调用 `prepare_move`，把卡牌确认插到 4011 前，再一起提交。指定骰点优先于一步/六步/乌龟持续步数，但不清除这些状态。

## 实现

五张卡分别在 Lua 验证请求并决定步数、成功响应，共享 `core/move_card.lua`。核心 `route.prepare_move` 只负责从当前权威棋盘准备真实路线，不再解析这些卡牌的业务字段；卡片事务提交前验证回合、库存、角色和地面版本。

Lua 返回一个确认包和原样路线数组之后才提交。漏包、换序、非法步数、准备后的脚本错误及混入其他状态修改都会在提交前拒绝，沿用 400B 恢复。无变化的地面计划仅用于版本检查，不消费路线上的物件；消费和落点交互仍由实际移动的状态机负责。

本次没有把一步/六步持续状态卡改成固定步数卡，也没有迁移付费骰子的数据库扣款事务。旧原生分支仍供未启用 Lua 的核心消费者使用。

## 编译与交付边界

`cmake --build server/build-goal-resume --target RichOnline.Server -j 4` 退出码 0，C++ 及全部 Lua 语法编译通过。实际 Lua 卡牌标记为 55 个。按用户要求未新增/执行测试，未启动服务或游戏。

用户正在使用 PID 54996 测试上一代程序；本轮仅生成候选 EXE 和 `build-goal-resume/scripts`，未覆盖 GUI 使用的 EXE，也未发送脚本重载。运行中服务的 Lua 快照保持原代；下次更新必须将候选 EXE 与配套脚本一起使用。
