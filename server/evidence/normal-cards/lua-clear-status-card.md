# Lua 清除卡 1078 迁移（2026-10-11）

规则依据迁移前 `boss_turns.cpp::auxiliary_card` 的135分支及 `RichonlineNpcSession::prepare_status_change`。本轮仅架构迁移，不声称新的客户端逆向或实机复现；按用户要求只编写代码和编译，不运行游戏或协议测试。

## 协议和原有行为

- C2S135/S2C40D7均为8字节；请求+6为零基目标角色，必须仍在场，响应+7归零。请求日历/库存槽/银行字段由 `card.prepare` 依据实际报文校验。
- 清除目标的附身与正值附身强度、计时炸弹及其归属、梦游、乌龟、停留、一步、六步、冰冻；清除目标与所有人的双向同盟计数。原分支不动状态免疫、攻击/伤害增益、资金、坐标。
- NPC 附身倒计时不是普通状态字段。若状态变化，`prepare_status_change` 同时准备时钟计划；版本检查后在同一房间串行提交中应用，避免角色状态和 NPC 内部倒计时分离。

## 新接口

`status.prepare_clear` 接受目标与上述八个可选字段名，拒绝不在场角色、重复或未知字段。`possession` 调用核心既有 `richonline_detach_possession`，`timed_bomb` 同时清空 owner。`relations.clear_actor` 只准备整行双向清零，与本动作其他关系计划互斥。Lua 模块列出实际业务字段并编码40D7；核心负责字段合法性、状态/NPC时钟版本及库存原子提交。

构建 `cmake --build server/build --target RichOnline.Server -j 4` 包含 C++ 与全部 Lua 语法编译；`git diff --check -- server` 检查差异格式。未运行实机测试，不能据此宣称客户端动画或长局续接已验证。其余48张卡文件仍可能是原生兼容、被动或本地入口。
