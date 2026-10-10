# 研究卡请求拒绝与提交错误边界（2026-10-10）

## 定位

最新日志native-54416.jsonl未匹配research/poison/out_of_phase/refused；本轮是源码审计，不声称实机复现。1181/1182/1183及大厅39/40已有会话接入，DEVELOPMENT较早条目中的未接入说明是历史状态。

boss_turns的155/156/157在try之前校验阶段、长度和日历，失败直接抛CodecError；与其他已修复卡牌的正常恢复路径不一致。156又在try内调用会提交共享状态的poison_card，将计划拒绝与共享账本/地面/地产的提交失效统一转换成400B，掩盖真实同步错误。

## 客户端与实现

live IDA实例5c7b48b1123e重新确认677920/40EB和677CC0/40EC；原始反编译存research-recovery-client.json。成功回复会扣卡并执行本地效果，40EC还在game校验之前增加game+60，因此拒绝不能伪造成功、重发40EC或提高服务端毒气次数。火焰40ED沿用research-fire证据。

- 155/157将阶段、八字节长度、日历和控制状态检查纳入无副作用的计划拒绝区，400B恢复，不扣卡、不放置陷阱、不切回合。
- 156先独立准备请求、原始角色状态和伤害范围；失败400B。战斗桥接新增默认关闭的recover_refusal参数，生产启用后只将纯伤害计划拒绝转换为400B。
- 角色/资金/地面/地产快照、关系及次数的失效检查和apply提交保留在恢复区之外；真实内部错误继续向上报告，不能包装成正常用卡拒绝。成功伤害、扣卡、关系解除及次数递增仍由原共享提交负责。
- 默认独立调用保持抛错契约。旧日历拒绝不产生成功包，不新增无法区分真实重复操作的重放缓存。

## 验证与安装

cmake --build server/build --target RichOnline.Server -j 4成功，git diff --check -- server通过。按用户要求未新增或运行测试，未启动服务或游戏。

确认服务进程不存在后备份并安装server/RichOnline.Server.exe，构建/安装SHA256均为31A740E1ABCBEEAF9EDDD1467FA621D38D2B469E5B34A7903A8BC8F628CABACD。备份与清单位于build-migration-backup/research-recovery-b8e22082db2f4906aa169ff48aff6a3b。游戏验收交给用户，完整goal继续。
