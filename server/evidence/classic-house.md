# 经典建屋卡1062

本轮接通经典会话C2S123/S2C40CB，不改BOSS建屋政策，不打开生产经典准入。
只编写代码、核对客户端静态证据和编译；不新增或运行测试，不启动服务或游戏。

## 客户端依据

`classic-house-client.json`记录18个函数的完整chunk、文件偏移、SHA256和反编译。
全部chunk与磁盘RnClient.exe逐字节相同；EXE SHA256为
`feeeac1bf9605690e8a774452456320125d7d3dbaa2dc73d529f8230c0677bc7`。

- `655D60`选格经`63E820/7E4440`规范为非保护的sprite11/12建筑格；
  `6928D0`写操作号123，报文8字节：+2日历WORD、+4槽位、+5背包、+6 signed WORD目标格。
  目标已经是建筑格，不能再按角色当前位置或道路property_ref解释。
- 经典分支要求`7E3D30`可升级且`63F500`不是商店。`63ED10→629DD0`
  判断模式0，上限5；`692030`排除kind8/9/10。该分支不检查所有权或查封，
  可以指定他人和无主地产，不要求角色脚下有地产，也没有扣款或许可证检查。
- `672AE0`消费40CB，排动画4/21并传目标WORD，然后扣一张卡并恢复操作。
  `634DA0`动画结束的经典分支：sprite12且level0时先`63F2D0`写kind3，
  再`7E3F30`加1级、上限5；最后`7E73F0`刷新建筑图像。
  因而住宅0→1、大型空地→1级贸易中心、已有非商店建筑+1，产权和计时不变。
- BOSS/模式4分支额外检查场景能力并可能初始化特殊建筑；不能用于经典模式。
  经典分支没有这些调用，也没有普通自有地产升级选择窗口或新的网络ACK。

## 实现

`RichonlineClassicProperty::prepare_card_house`按目标建筑格建立前后快照，
拒绝满5级、商店和保护建筑；大型空地改kind3后加1，其余只加1。
`classic_property_card.cpp`接受123的8字节请求和1062库存，复用既有Lua
`card.prepare`、`property.prepare(operation=house,position=...)`编排。
对position追加整数类型核验，回包须逐字节等于40CB确认。

会话沿用行动阶段、控制状态、收容状态、库存、活动玩家、位置方向、地产和
研究状态检查。全部准备成功后统一提交扣卡与地产变化；拒绝请求返回400B恢复操作。
建屋不改变产权、不解除研究登记，不触发资金事务；不复制BOSS专有规则到经典模式。
随机池开关沿用card_1062.lua既有配置，不在本轮扩大其他模式的可用范围。

## 固定构建与本机交付

源码提交`6dae9fe7eacd3aee40589d07dd564dcab52acd1c`，固定tree
`8526c3a1a2c80ecf392fd7a2ed1c771ada9ad9d3`，已推送并核对GitHub main远端引用。
本回执的后续文档提交不改变该二进制的源码身份。

从该tree导出`server/build-classic-house-source/server`，独立构建到
`server/build-classic-house-fixed`。Clang22、Ninja、Release、BUILD_TESTING=OFF，
构建目标RichOnline.Server退出0，包含全部178个Lua模块的语法编译。
静态diff检查通过，未新增或运行测试，未启动服务或客户端，未部署或重启线上。

交付前检查本机服务进程，目标EXE未运行；备份到
`server/build-classic-house-fixed/RichOnline.Server.before-6dae9fe.exe`后更新
`server/RichOnline.Server.exe`。固定构建与本机EXE SHA256均为
`25CA77389E4BEB4192EB8C2025238068299687C2E62307BFF2FDA061BF8BE2B9`。
178个本机Lua文件与固定源码、构建输出逐项哈希一致，文件数量一致。
编译通过不等于实机玩法验收；生产经典准入仍未开放，完整服务端goal继续推进。
