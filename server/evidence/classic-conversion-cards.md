# 经典模式建筑改造卡 1064–1068

客户端 `RnClient.exe` SHA256 `feeeac1bf9605690e8a774452456320125d7d3dbaa2dc73d529f8230c0677bc7`。
`normal-cards/classic-conversion-client.json` 保留 6563B0/6565A0/656790/656980/656B70 的请求构造、
6730A0/6732B0/6734C0/6736D0/6738E0 的回复消费和 681110 的本地 kind 更新。

经典模式的 125–129 请求均为八字节：日历、手牌槽、group0、目标地产 WORD。
五个成功回复分别为 40CD–40D1，回显请求后四字节。目标须为 sprite12、正等级，
不能是 kind8/9/10，也不能已经是目标 kind；原生入口不限产权。
681110 仅改 kind 为 2–6，保留等级、产权和既有登记。

服务端复用经典卡牌的回合、日历、手牌、Lua 响应和共享提交校验。
`prepare_card_conversion` 只准备目标地产的 kind 变化，成功时连同扣卡提交；
无效请求按现有卡牌入口恢复 400B，不扣卡。经典研究登记不在这条改造卡
提交时主动解除，后续原生日历扫描根据新 kind/等级/产权处理。

此项只接通改造卡事务。经典模式中贸易中心、饭店、电脑公司、房产公司的
落点业务尚未补齐，生产经典准入仍关闭，不能据此声称这些建筑已经完整可玩。
验证限于 Release 编译、Lua 语法编译和限定 diff；未新增或运行玩法测试，
未启动本机服务或客户端。上线回执待固定源码发布后追加。

## 上线回执

2026-10-12 已部署并核验源码提交 `3255d79efe5d5df120c9046e48470f9de388dd9f`，
源码 tree `561a973ad60f0766b26a33ed905b221c4d6c6631`，release `3255d79efe5d`。
固定源码独立 Release 与 173 个 Lua 语法编译通过，BUILD_TESTING=OFF。

- EXE SHA256：`E6A2CF541FFE9C68A703A06341F1E5571A2328BAA0BAD45E218F42D03C759CC2`。
- ZIP SHA256：`90F0CA31B209ABFE546F57DF08D210F8AD03BEEB5D631569020A8EA54AB6A304`；208个文件逐项大小及哈希核验。
- 实际 PID 5608，instance `5608-122770021824800`；进程与 Running 计划任务均指向 `D:\richonline\releases\3255d79efe5d\RichOnline.Server.exe`，实际文件哈希一致。
- 在线数据库备份 `D:\richonline\shared\data\backups\accounts-1791752443557513.sqlite3`，319488字节；部署备份 `D:\richonline\backups\20261011210043-3255d79efe5d`。数据目录仍为 `D:\richonline\shared\data`。
- 配置逐键比较仅 `richonline_boss_game.client_root` 随新 release 改变；其余包括商城日期、BOSS地图准入配置保留。
- 六项监听 Ready 为 true；18600/18602/18604/18605/18606/18680公网TCP通过。两个大厅列表HTTP200，CP950频道与公网地址正常。
- 本机服务未运行，EXE备份后同步为同哈希文件，173个本机Lua逐项与manifest一致；未启动服务或客户端。

同时复核用户提出的 BOSS 回血同步：此前 `4a1b52e927709199854ce46e6ebe97e7da619968`
已实现原生回血及日期狂暴镜像，属于本次提交祖先。详见 `native-boss-recovery.md`。
当前客户端 SHA256 与该研究证据一致；本次没有取得新的回血不同步实战日志，
因此不能将客户端显示回血单独判定为服务端未回血。部署健康检查不等于玩法验收。
