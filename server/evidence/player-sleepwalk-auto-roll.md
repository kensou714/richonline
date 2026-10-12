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
发布结果在完成后补充。
