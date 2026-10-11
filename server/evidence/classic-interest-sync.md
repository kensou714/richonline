# 经典月初存款利息同步

## 客户端依据

2026-10-12 静态复核原版 RnClient.exe，SHA256
`feeeac1bf9605690e8a774452456320125d7d3dbaa2dc73d529f8230c0677bc7`。
`classic-interest-sync-client.json`记录21个函数的全部chunk哈希，IDA字节与磁盘PE逐字节一致。

- `7C0C50`的`7C1902..7C1955`检查日期day=1、current=anchor以及`63ECA0`模式门：
  模式0，或模式2且副模式0。当前改动只接入经典模式0会话，不扩展其他模式。
- `7D8810`首次轮首只将计数种为1，不推进年月日；因此开局恰逢1日也有利息。
  后续日期推进见`7D8840`，当前只支持与原客户端一致的2004～2034年，越界拒绝。
- 日期门通过后排两字节本地`6041`，位于节日和开奖前，不受节日scripted_event门限制。
- `67E8A0`遍历角色，只检查`63E7D0`活动标志，不排除住院、监狱、绑架。
  `63F650`读取P+1508存款，signed idiv10，`7FA0A0`增加存款并记录收入。
- 客户端显示UI4文本131“銀行加發10%儲金利息”，等待1800ms，没有加息C2S确认。
  服务端不能额外发送加钱包、本地6041或第二条4010，否则可能双加。

## 本轮实现与边界

`prepare_richonline_classic_interest`仅准备活动角色的完整资金快照及更新；每人的利息是
自己的非负存款整数除10。现金、点券、押金保持不变，零利息仍参与快照核对。
未知存款、无活动角色、非法活动标志或存款超过signed DWORD上限时拒绝；不环绕、不钳制。
所有角色通过现有`ledger.commit_batch`统一校验、原子提交，正存款收入沿用账本收益政策。

独立Lua模块`events/classic_interest.lua`生成金额意图，注册`interest.classic`；C++检查完整
结果及整数类型，不允许脚本改动角色、金额或附加字段。Lua不可用的纯C++调用沿用同一公式。

`classic_session::begin_turn`在内置节日前入账，仅轮首且真实日期1日触发，成功后按日期去重。
不增加消息或ACK，不增加等待，节日和开奖续接回调不会再走这一步。`turn_start`业务读取
已加息的账本，不得重复加息。超过2034年不套用系统年份，避免不可同步的日期回退。

本轮未开放生产经典准入，不能以利息接入代表完整经典玩法或完整日历已经完成。
未修改BOSS回血逻辑；已发布的原生回血与狂暴修复由当前版本继承。
按用户要求不新增/运行测试，不启动本机服务端或客户端；仅编译、静态核验及发布健康检查。

## 编译及上线回执

2026-10-12（本地时区）源码提交`0ce3a5d73bb6b087652dc53c3af7478b840dff0c`已推送GitHub
main并核对远端引用。固定源码tree为`17fcb06bda5ca27c9a8b60a6292cd6bb3516a8a3`，
独立Release构建和173个Lua模块语法编译通过，BUILD_TESTING=OFF。仅提交本轮9个文件，
保留其他会话的文档、测试和旧利息证据。后续回执文档提交不改变二进制源码身份。

- 线上release：`0ce3a5d73bb6`，实际PID `4712`，instance `4712-115147311625800`。
  计划任务与Win32_Process路径均为`D:\richonline\releases\0ce3a5d73bb6\RichOnline.Server.exe`。
- EXE SHA256：`C58F204A9EC4840D11FEC7DECBF9545A43DA7BB804B4692D3FCB226092DE5592`。
- ZIP SHA256：`48DA4CCE29D9E96B69828AC9363F00CAC7CE3F5BE98510CA505C20EE0EA2FF93`。
  208个运行文件的ZIP内容、长度和SHA256均与manifest一致。
- 数据目录`D:\richonline\shared\data`；在线DB备份
  `D:\richonline\shared\data\backups\accounts-1791744820830195.sqlite3`；部署备份
  `D:\richonline\backups\20261011185340-0ce3a5d73bb6`。
  安装器使用ExpectedInstance正常停止旧实例，未覆盖数据库。
- lobby/http/gameListener/black/intro/inquiry均Ready；18600/18602/18604/18605/18606/18680
  六个公网TCP连接成功，两份大厅列表HTTP 200；CP950解码的三个频道均为103.156.25.81:18600。
- 兼容商城日期、全BOSS测试地图解锁及新release资源路径已核验。本机EXE经备份后替换为
  同哈希文件，173个本机Lua文件逐项匹配发布manifest；未启动本机服务。

这里只确认编译、发布完整性及健康状态，未执行玩法测试。经典生产准入继续关闭，
`gameReady=false`仍代表整体能力边界，不能据此次部署宣称完整经典模式可玩。
