# 玩家梦游自动掷骰

用户报告线上玩家梦游时卡住，正常应自动投骰。线上release89923befd953、
PID9592的原生日志在2026-10-12T00:20:49.465Z记录黑贝贝房间：
`richonline_controlled_roll_recovered actor=0 counter=38 policy=server_timeout_ordinary_roll`。
这证明该回合依赖服务端30秒超时才推进，而非必须等待玩家主动操作。

## 修正

BOSS会话中玩家的梦游计时和睡神附身都经controlled_roll_actor判定。
await_roll及请神卡恢复行动分支已有统一的自动掷骰deadline；原默认值30000毫秒。
默认改为0，在下一次宿主poll中使用现有controlled_move生成普通4011路线。
不等待客户端0010，客户端正常先到的0010仍可按原路径推进。
accepted_controlled_move按日历去重迟到0010，避免再次抽骰、扣金豆或移动。
此延迟是服务端策略，不声称从原客户端恢复出0毫秒计时常数。

冰冻、停留、入狱、新闻和落点等待仍由各自阶段处理；仅Phase::roll的受控玩家
进入自动移动，不把其它等待强行结束。经典多人会话尚需独立核对。

遵循用户约束：只静态检查并编译，不新增或运行测试，不启动本机服务/游戏。
## 编译与发布

固定tree：`9b0df753a1f00a77c0ed95656702b00d0f243cd7`，独立目录Release编译退出0。
源码提交`8c26dbe59536ab57ff44eb107d85759342f4d249`已推送并核对GitHub main。
发布包SHA256：`909FE2304FB55CF5D0894A6FE1504922EB97A2DC9A44B77F6915C3C860905CEF`。
EXE SHA256：`B69ECDF6CA4F4E714E5F46DF17E590812410D12C825FAFD5E016AA555F30CE16`。

线上release`8c26dbe59536`，PID11220，instance`11220-135196050793200`。
214个发布文件哈希和长度核验一致，179个Lua模块，计划任务与实际进程指向同一版本。
持久目录仍为`D:\richonline\shared\data`；上线前数据库备份为
`D:\richonline\shared\data\backups\accounts-1791764869605360.sqlite3`。
配置/任务预归档在`D:\richonline\backups\20261012002726-preflight-8c26dbe59536`。
本次配置除资源根目录外与更新前一致，保留1:1000兑换及商城资源。
商城资源仍来自提交`89923befd9537397505d43e49f2e601abacf4a75`。

六类监听就绪，公网18600/18602/18604/18605/18606/18680连通，
两个服务器列表HTTP 200。gameReady=false仍是整体玩法未完整的能力边界。
以上不替代客户端实机验收；没有运行本机服务、游戏或测试。
