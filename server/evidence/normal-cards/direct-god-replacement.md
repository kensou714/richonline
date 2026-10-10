# 财神卡与福神卡替换强化状态（2026-10-10）

最新日志native-54416.jsonl未匹配fortune/wealth/temple/strength，本轮是源码审计发现，未声称实机复现。

## 证据与修正

live IDA实例5c7b48b1123e、RnClient.exe，原始反编译见direct-god-replacement-client.json。

- 673AF0（40D2/1069）和673D50（40D3/1070）在角色已有任何附身时，先经610C1A检查并排6050，随后扣卡、排6051附财神0/福神3。即使新旧为同一种神明也先卸除。
- 6050的卸除行为沿用ground-aura-client.json中的7F7D50→7016B0/7FDBA0：清1488/1489/1490，正强化1740归零，1744不另写。
- npc.cpp两个纯规划器原来只覆盖possession，残留旧神庙强化。现在直接财神卡和直接福神卡在预计状态中先调用richonline_detach_possession，然后附新神明；权威状态仍在会话原有扣卡/时钟提交处写入。
- 福神规划器还用于神庙/请神卡奖励，因此仅对fortune_card1070来源新增卸除；不在奖励规划中重复卸除已处理的附身。地面和请神卡替换已由上一轮修复。其他移动状态不受影响。
- 保留40D2后金钱轮盘、40D3/4023顺序、随机两张奖励及满手牌续接。失败规划不提前清除权威强化或扣卡。

## 开店卡核查边界

652F40调用606B52→63E290要求目标地产D+0==11，且已归属、等级非零、非商店kind1。当前BOSS地产装载只支持sprite12；不能将12类型大建筑伪装为11类型商店。开店卡1034本轮保持400B拒绝，真正支持需闭合经典小型地产装载、商店落点和相关战斗形状，不能仅返回40B3。

## 编译及安装

cmake --build server/build --target RichOnline.Server -j 4成功，git diff --check -- server通过。未新增/运行测试、未启动服务或游戏。确认服务进程不存在后备份并更新GUI使用的server/RichOnline.Server.exe。

安装和构建SHA256：7E13B63C4C2A11DCD15D000A28F1ABF1D4021CADF5BE7A26A9A0B42209A8FD9B。备份及清单：build-migration-backup/direct-god-91513abfff9247229d73b94a663d1342。游戏验证由用户完成，完整goal继续。
