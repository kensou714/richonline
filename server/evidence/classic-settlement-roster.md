# 经典结算角色顺序校验

## 问题与身份来源

RichonlineClassicTerminal按participants的顺序，把各槽的收益、胜负和战绩写给对应role_id。
此前会话装配只检查局号、房间、人数、押金和共享账本指针；同人数的名单即使调换角色仍能通过。
这会使准入层排序错误进入结算阶段，把胜负和奖励归给错误的角色。
此为源码审阅发现的接入缺口，不是用户已经复现的线上故障；生产经典模式仍未开放。

身份映射依据当前源码：

- server_lobby_connections.cpp进入频道时令actor等于认证选角的selected_role。
- richonline_classic_startup.cpp将玩家按实际房间槽排序，核对玩家identity与房间actor相等。
- classic_session.cpp逐槽核对source.players.identity与board.participants.lobby_identity相等，
  且核对所有接收者的开局板和资金快照一致。

## 修改

validate_identity改收实际棋盘角色数组，保留局号、房间、人数、押金和共享账本校验，
增加每一槽lobby_identity非负且等于结算participants[slot].role_id的检查。
同人数换序、换人或负身份均在会话装配时拒绝，不能进入后续按槽分配奖励的路径。
不截断64位数据库role_id来比较16位协议身份；超出协议范围的角色也无法通过相等比较。
账号与角色归属、押金凭据仍由持久层事务核对；本次不推测地产估值或修改月限胜负规则。

## 验证边界

静态核对唯一调用点与认证身份链，固定提交Release构建及整包Lua语法编译。
按用户要求不新增或运行测试，不启动本机服务或客户端。
这项修复不等于生产经典模式已开放，也不证明地产价值公式已经查明。

## 发布结果

- 源码`ce1456046d5518d34ae3b26c85dd0e51fa7f8245`，tree`d5451425ed207f4f43afa43e672e9f3017bbfe8f`，已推送GitHub main。
- 固定提交Release构建及167份Lua语法编译通过；未新增或运行测试。
- 线上release`ce1456046d55`，PID5888，instance`5888-99681269547600`，
  真实进程与任务均指向`D:\richonline\releases\ce1456046d55\RichOnline.Server.exe`。
- EXE SHA256 `E8A7CBA7C81BA0CD3C6235DADE8D0AC0203001DDE916A72587725A224EFF0A7C`；本机已同步相同版本，未启动。
- 数据库备份`D:\richonline\shared\data\backups\accounts-1791729354820653.sqlite3`。
  保留`D:\richonline\shared\data`、商城日期兼容及全部BOSS地图测试配置。
- 六类监听ready；18600/18602/18604/18605/18606/18680公网TCP成功，两份服务器列表HTTP200。
- 本地收据`server/build-goal-resume/release-ce1456046d55-receipt.json`及同版本verified/process/bootstrap-after文件。
  后续证据提交不改变部署源码版本，亦不代表多人结算实机验收。
