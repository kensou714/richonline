# 财神1069与福神1070的Lua编排和核心准备事务

日期：2026-10-11。仅代码、静态差异审阅及编译；未新增/执行测试、未启动服务或游戏、未安装候选EXE。

## 沿用的协议和状态依据

- `npc.cpp::decode_richonline_wealth_card` / `decode_richonline_fortune_card`：130/131请求均为6字节，+2日历、+4零基槽位、+5主背包0。
- `plan_richonline_wealth_card`：六字节40D2替换旧附身为NPC0，设置资源NPC0的affix时钟，随后等待34。卡牌阶段不直接修改余额。
- `plan_richonline_fortune`：福神卡先六字节40D3，再八字节4023；后者携带两个16位卡号。客户端逐次插入并继续本地流程，没有额外确认请求。
- `npc_session.cpp`既有财神/福神入口要求NPC空闲、模式3、真人施放者与权威状态一致。财神设置summoned_card来源的pending；福神立即restore_action。
- `boss_session.cpp`的fortune_selection在扣卡后的库存上先抽第一张，再以第一次投影库存抽第二张。资源 `ChanceResources::add`满手牌直接返回原库存；有空位时插入并按资源执行组合。
- 本轮无新增客户端反编译；协议和算法来自当前已有实现，不把静态对应与编译成功等同于实机通过。

## 事务拆分

Lua卡模块指定NPC及成功消息：1069调用 `npc.prepare_attach({npc=0})` 后构造40D2；1070指定NPC3，再调用 `inventory.prepare_fortune`，构造40D3和4023。旧安装EXE缺少新能力时，在调用card.prepare之前回退原生入口。

`prepare_card_attachment`复核NPC会话与施放者，准备清除旧附身强度、写入新神及资源时钟，保存时钟代数和原始状态；NPC0计划另保存转盘日历。`commit_status_change`匹配原状态与时钟、整个会话仍空闲后才写入状态和pending，不新增提交后可能失败的分配。

`prepare_richonline_fortune_rewards`从既有福神计划中抽出，原生落点/神庙/卡牌与Lua入口共用按序插入、合成和面板文本长度校验。它返回投影库存与规范4023，不直接改库存。生产抽卡池继续由已有Lua开放策略和资源/地图允许规则约束，不生成商城500–519卡。

Lua完整返回后，核心精确校验40D2单包或40D3→4023双包；福神漏调用奖励准备、漏包、换序、改卡号以及混用其他状态/资金/坐标/库存计划均拒绝。提交前再核对角色、回合、日历、位置、库存与NPC状态/时钟。财神的超时时刻也在提交前计算，提交只切换已准备好的NPC等待；福神保持掷骰阶段。

财神后续34与超时处理仍使用原有 `resolve_roulette`，包括资金快照、零金额、破产和终局。卡牌脚本不伪造请求、不提前给钱。网络发送失败依旧不等于已经提交的内存状态回滚。

## 验证范围

`cmake --build server/build-goal-resume --target RichOnline.Server -j 4`完成C++链接及全部Lua语法编译。修改范围 `git diff --check`通过。60张卡的 `implementation="lua"`静态计数与文档一致；其余32张定义仍需继续推进，整个NPC与卡牌目标未完成。

候选EXE SHA256：`CC431FE2445E4BFEBBF84068B2B2C1D6AE9B7EDFFE162D7123DD696C7391DFD4`。

安装EXE SHA256仍为：`F9124C7EFCFD6CBB73F8E2DD0E72C8BC7031C8A0DCAD6E27D50540FB3C62737C`。
