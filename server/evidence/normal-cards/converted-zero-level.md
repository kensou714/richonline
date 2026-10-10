# 改造后的0级建筑与战斗提交（2026-10-10）

日志native-54416.jsonl未匹配property_combat_transition_invalid/conversion_card/building_invalid/missile_base，本轮是源码状态链审计，未声称实机复现。

## 根因与客户端证据

live IDA实例5c7b48b1123e、RnClient.exe，6823A0反编译见converted-zero-level-client.json。建筑改造先写新kind，再读取当前角色的该建筑能力；当前等级高于能力则直接写能力值。能力0时仍保留新kind，不执行拆除逻辑清成-1。

prepare_conversion_card已正确允许该结果。比如等级3改造为kind12且能力0，提交后为kind12/level0。但下一次prepare_combat对所有地产逐条校验，即使建筑完全未变也要求level0对应kind-1。因此基地计时、地雷到期、普通攻击或其他地产拆除都可能抛richonline_property_combat_transition_invalid。异常发生在后续共享事务准备，不能通过伪造卡牌拒绝修复。

## 修正

战斗地产校验区分真实降级与保持原状：只有从正等级降至0才要求kind-1；原来已经为0级时保留原类型。其余禁止升级、转让给新所有者、改变地产足迹等规则保留。建筑改造、换地、换屋仍走它们各自的准备器。

此改动让共享提交兼容已接受的合法状态，不把0级特殊建筑当作有效升级或发射来源。基地计时仍排除level0，落点建造仍依照空地分支。

## 构建与安装

cmake --build server/build --target RichOnline.Server -j 4成功，git diff --check -- server通过。按用户要求未新增/运行测试，未启动服务或游戏。确认服务不存在后备份并安装GUI路径server/RichOnline.Server.exe。

构建与安装SHA256：19051DADFA18B238D05195CF7456C8C95DB71CDB1BD240124D7C29DCAD4231AD。备份及清单：build-migration-backup/zero-level-f406250ef19d49a48a6c535948061b91。实际游戏效果由用户验收，完整goal继续。

## 后续边界

6806D0在mode3所有权变更后也调用基地登记7E5E00，后者在空槽新建记录，而旧登记删除只在mode4分支可见。客户端同地产多登记的后续影响还需独立核对；本轮不据此改变已实现的每地产单时钟策略。
