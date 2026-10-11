# 原生BOSS回血与光环结算顺序

2026-10-12复核“客户端显示回血、服务端可能未同步”。原生恢复此前已接入，
本轮发现并修正的是同回合光环破产时漏记恢复的边界，不据此断言它就是玩家所见那局的原因。
本轮未运行游戏或玩法测试，也未重启、部署线上实例。

## 客户端证据

`native-boss-recovery-order-client.json`保存6个函数的chunk范围、磁盘偏移、SHA256及
反编译内容。所有chunk逐字节匹配当前RnClient.exe，整文件SHA256为
`feeeac1bf9605690e8a774452456320125d7d3dbaa2dc73d529f8230c0677bc7`。

- `7C0C50/LABEL_134`先调用610BE8→7FA360检查资格、61136D→7FA3F0计算恢复量，
  通过60CA02排本地6060及显示消息，再由601044→7D6A40清P+1650资格。
  后面才经606AEE→7CEA20处理状态4/6的神明光环。
- `7FA360`要求P+1650有效、资源恢复量正数、现金严格低于原始bossInitCash。
  达到上限时不进入恢复分支，也不清旧受伤资格。
- `7FA3F0`在原生狂暴时先将基础量存float，再乘恢复倍率、加0.5取整并截到上限。
  非狂暴不经过这次float转换。`7FA050`消费6060时直接加钱，不再裁剪。
- `7CEA20`的目标筛选排除BOSS。负面光环排扣款后才发生玩家破产；不能倒过来用
  这个后续结果取消已排入的BOSS恢复。

## 服务端修改

原`boss_turns.cpp`先准备光环结果，并用`aura_bankrupt.empty()`限制原生恢复。
因此BOSS满足回血条件、又在本轮用负面光环击败玩家时，服务端没有记录客户端已显示的回血。
现在先准备BOSS恢复，再追加光环事务，使用同一`commit_sequence`依次校验和原子提交，
提交成功后清受伤资格，最后处理光环破产。光环不更新BOSS，因此两组准备快照不冲突。

原生恢复独立为`boss_recovery.cpp`和`bosses/native_recovery.lua`；C++核验状态、
数值域和Lua结果，Lua只返回恢复意图，不修改账本或发包。恢复分支与金额独立，
即使合法倍率令恢复量取整为0，也遵循原生清资格逻辑。实际已知关卡倍率均为正数。

每次配置了原生恢复的BOSS回合记录`richonline_native_boss_restore_check`，包含
game、turn、day、eligible、cap、before、amount、frenzy；成功恢复仍记录原有
`richonline_native_boss_restore before/after`。判定日志中的before取准备时快照，
不受同回合装备回血影响。没有资格或达到上限也有判定记录，供后续实机反馈定位。

本轮不发送额外回血包，避免客户端重复回血。黑贝贝、阿战伯、赵灵儿没有原生恢复
配置；空中花园和装备回血仍沿各自独立路径处理。此前线上PID/日志记录不当作当前状态。

## 验证边界

已完成客户端静态字节核对与源码审阅。固定源码tree
`58d2a0902fe2178f268dec976e88eefb6e14b180` 独立Release构建成功，
构建目标`RichOnline.Server`内的全部178个Lua模块语法编译通过；源码提交
`317f63a3447829fd7c06e4aed15e2a0de6c97764`已推送并核对GitHub main远端引用。
本机`server/RichOnline.Server.exe`在未运行时备份旧文件并交付新同代文件，
SHA256 `0FC813378E12D3265561F29811D00A497C20FD49F771A2B458691E79CBB9E95A`；
178个本机Lua模块与固定源码及构建输出逐项哈希一致。旧EXE备份位于
`server/build-native-recovery-order-fixed/RichOnline.Server.before-317f63a.exe`。
按用户限制不新增或运行测试，不启动服务或游戏。不能将编译通过视为实机回血同步验收。
