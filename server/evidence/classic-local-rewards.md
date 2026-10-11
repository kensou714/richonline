# 经典模式点券与兑换格

经典共享会话此前没有内置5/6/7/57分支，业务未接管时会报静态落点未实现。现在复用BOSS已用的只读资金准备器及现有Lua模块，接入无地产引用的三类点券格和57兑换格。生产mode0准入仍关闭；这不是完整经典玩法上线声明。

## 客户端依据

`classic-local-rewards-client.json`保存23个函数/跳板的完整伪代码、函数窗口地址和SHA256。全部窗口逐字节匹配当前磁盘RnClient.exe，文件SHA256为`feeeac1bf9605690e8a774452456320125d7d3dbaa2dc73d529f8230c0677bc7`。这是静态核对，没有执行或修改客户端。

- `7C54B0`入口沿用已有`classic-portal-client.json`证实的模式4合成角色排除门。脚本事件83830不为-1、睡神、梦游、冰冻会跳过静态格。
- 5/6/7分支分别取80/50/30，排6062本地加点券；模式3合成BOSS跳过，经典真人不跳过。构造器`6119B2→694460`写入6062。
- 57分支真人不足25点券时只显示提示181；足够时扣25点券，加2000现金。合成BOSS只加2000现金。构造器`60CA02→693320`写入6060。
- 这些分支最后返回1，沿既有静态阶段进入phase2及phase6。4013已触发本地资金更新，不能额外发送资金增量造成重复计入。

## 实现与静态审阅

`prepare_richonline_ticket_landing`增加mode0真人0..3支持；`prepare_richonline_special_landing`只增加mode0的57，不扩展58。BOSS仍要求双角色及正确合成标志，且不能借经典phase6授权绕过其碰撞检查。经典保留真实同格信息，通过宿主已有phase6授权先执行静态效果，最后由complete统一碰撞及选择方向。

经典会话在外部services.landing未接管时处理四类格子，拒绝混合地产引用和未知/活动脚本事件。先生成资金前后快照与唯一4013；有Lua时调用原tiles.tile_5/6/7/57，准备回调只允许一次，并核对完整输出、金额、消息数量及逐字节内容。没有脚本时沿用同一准备器，不另写奖励公式。

账本提交前重新确认资金版本、行动角色状态、位置、活动资格、脚本状态及phase6授权。受控角色或兑换不足25点券只确认落点，不改金额；达到边界时按已有有符号资金范围拒绝溢出。共享移动上报仍先全员汇合后触发一次落点。日志`richonline_classic_local_reward`记录角色、位置和资金前后值。

本轮不新增或运行测试，不启动本机服务/客户端；仅静态逆向、代码审阅、固定源码Release编译及Lua语法编译。完整经典准入、地产资产估值公式及其余业务仍需继续；NPC购地延时修复已在前一版本上线，弹窗恢复仍待用户实测。

## 发布记录

- 源码提交：`8c0121198b871ab64e87e49d5db33a5cc22b64cb`，已推送GitHub main；固定源码树`02cd569079cf32e9adaaacb427a4fe28bc7b5de8`的Release编译与166份Lua语法编译成功。
- 线上release：`8c0121198b87`，PID12072，instanceId `12072-93392513914500`。
- 实际进程与计划任务均为`D:\richonline\releases\8c0121198b87\RichOnline.Server.exe`；EXE SHA256为`88A8D80036D67448DC9054F8695BD6638245CF18D3DC6286BF13FD8EC428A4A7`。
- 部署前已在线备份数据库并通过ExpectedInstance正常停止旧版；持久数据目录仍为`D:\richonline\shared\data`。
- 六类监听ready，18600/18602/18604/18605/18606/18680公网TCP均连通，RichNetLogin.txt及RichNetServer.txt均HTTP200。
- 保留商城compat_2021_v1、richonline-inventory-date-2021-v1及全部BOSS地图测试开关。本机EXE同哈希、166份运行Lua与发布包一致，未启动本机服务。
- 私有完整收据见`server/build-goal-resume/release-8c0121198b87-receipt.json`；未运行玩法测试，未宣称经典生产玩法或NPC购地弹窗已获实机验收。
