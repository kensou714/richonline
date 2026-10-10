# 服务端开发交接

## Lua 移动状态卡入口修正（2026-10-11）

- 1039 乌龟卡、1040 转向卡、1041 停留卡、1042 梦游卡、1079 一步卡和1084 六步卡使用 `motion.prepare` Lua 入口；C++ 继续负责真实道路、动态物件、状态时钟、路线回包和原子提交。
- 梦游卡对自己使用时在提交阶段恢复掷骰续接，避免卡牌成功后错误停留在移动/结束阶段；受保护目标仍返回原生400B恢复包并不扣卡。
- 1080–1083 二至五步卡保留 `native_compatibility`，继续走固定步数规划器；`motion.prepare` 明确只接受104/105/106/107/136/141，避免把137–140误送入移动状态计划器。
- 当前源码与脚本已完成静态差异核对；本环境未提供可执行终端调用，尚未生成新的 EXE，也未覆盖 GUI 安装版。不得把旧商城版本 EXE 与本轮移动卡脚本混配发布。


## Lua 商城购买策略（2026-10-11）

- 从最新日志45308确认购买拒绝为`inventory_date_year_unrepresentable`，原2005纪元的4位年份无法编码2026限时商品；没有改客户端/数据库日期版本或伪造永久期限。
- 新增`mall/purchase.lua`，迁移购买资格和期限规划；核心复核资源期限、编码日期并沿用原子扣款/发货/收据及profile刷新。商城操作日志增加商品编号/键/币种/纪元。
- C++和全Lua语法编译通过；不运行游戏/协议测试。商城实际购物仍受日期兼容限制，证据与接口边界见`evidence/lua-mall-purchase.md`、`LUA-SERVER.md`。
- 差异检查通过，确认无服务进程且旧EXE哈希符合上一代快照后，已更新GUI使用的EXE，SHA256 `D50355F4315450B89F92D3FE4A9B030DF26E762BA065AA46444F0E115C4FA96F`。配对备份和回执：`build-migration-backup/lua-mall-policy-645118b2c4804e668b09e6b761df8002/`。

## Lua 清除卡状态事务（2026-10-11）

- 清除卡1078改为Lua独立编排，累计44张卡由Lua规则/编排。Lua列出八类状态和整行关系清除，C++准备NPC附身倒计时、版本校验并在完整回包后与扣卡一起提交。
- 免疫、攻击/伤害增益、资金和位置沿用原有保留语义。协议与边界见`evidence/normal-cards/lua-clear-status-card.md`和`LUA-SERVER.md`。
- C++与全部Lua语法编译、`git diff --check -- server`通过；按用户要求未运行游戏/协议测试，实机验证由用户完成。
- 确认无服务进程后已更新GUI使用的`server/RichOnline.Server.exe`，SHA256 `27286EA8F3C540E1E54C6E18A1C7E76A807C158443578F0EDE2DC0607B3E1914`。`build-migration-backup/lua-clear-status-cae652df0627430ab6b3ae88af7e3952/`保存旧EXE/旧脚本和新脚本快照、回执，回滚按代配对。

## Lua 角色位置卡迁移（2026-10-11）

- 传送1116与换位503改为独立Lua编排，累计43张卡。新接口`actor.relocation_snapshot`、`actor.prepare_positions`让Lua选择目标和轮换关系，C++校验道路/原坐标并与扣卡一起提交；不改变原有落点消息序列。
- 毒卡1182暂保留原生战斗事务：每个命中格对临时余额重算伤害，破产终局须与库存/资金同一计划完成，不能以多次`funds.prepare`代替。迁移边界见`evidence/normal-cards/lua-relocation-cards.md`。
- C++和全部Lua语法编译、`git diff --check -- server`通过；按用户要求未运行游戏/协议测试，实机验证由用户完成。
- 确认无服务进程后已更新GUI使用的`server/RichOnline.Server.exe`，SHA256 `D2110BF13E24E816426EA346C1E26CD5B25076822FCA83C2C2EA2307CC6E8584`。旧EXE/旧脚本与新脚本快照和回执位于`build-migration-backup/lua-relocation-4bdba85db64f4003b7db0fe5a858ac0c/`，回滚按代配对。

## Lua 辅助卡迁移（2026-10-11）

- 同盟1060、察看1072、飞吻1130、武器条约1115、开路1061改为独立Lua规则与回包编排，累计41张卡使用Lua规则/编排。新增对称关系准备、主库存按卡种清除、现有十步寻路预览接口；库存/地面/关系在回包构造后提交。
- 大厅39/40投票已有成员、超时、结果应用闭环，保留其现有原生事务；毒卡1182及移动/状态卡等仍走原生兼容入口，未宣称全Lua完成。证据与边界见`evidence/normal-cards/lua-auxiliary-cards.md`、`LUA-SERVER.md`。
- C++目标和全Lua语法编译、`git diff --check -- server`通过；按用户要求未运行游戏/协议测试，实机验证由用户完成。
- 确认无服务进程后已更新GUI使用的`server/RichOnline.Server.exe`，SHA256 `57D194BA1B0962E21822A809AEE2819ACA7B0AE594F1815B1FA94CE5FD574DA0`。`build-migration-backup/lua-auxiliary-0a96fd88e2fe4c57972c681b2fd69620/`同时保存旧EXE/旧脚本和新脚本快照、回执；回滚须按代配对。

## Lua 研究陷阱与净空卡继续迁移（2026-10-11）

- 1181 冰冻陷阱、1183 火焰陷阱和502净空卡已从整包 native 兼容入口迁入 Lua；Lua 负责请求字段、地图范围、静态格/角色/动态物件筛选和40EB/40ED/40F0回包，C++ 负责版本化事务与踩中/伤害/时钟等既有核心状态。
- 新增 `map.info`、`research.traps`、`ground.snapshot`、`ground.prepare_batch`、`ground.prepare_remove`，`map.cell` 增加在场角色与动态物件占用，`game.snapshot` 增加 `can_act`。批量火焰放置允许空结果并仍消耗卡，净空允许空地图成功。
- 所有 Lua 文件包含中文职责注释；`cmake --build server/build --target RichOnline.Server -j 4` 和 `git diff --check -- server` 已通过。按用户要求未启动服务、未运行测试，实机通信由用户验证。
- 确认服务进程退出后已更新 GUI 使用的 `server/RichOnline.Server.exe`，SHA256 `4FD567A9C17F955A6E2A303263D0187022EE783150573F3AC7B80A6771142C03`。旧程序和当前脚本快照回执保存在 `build-migration-backup/lua-research-ground-a3dca0ba068344029dc461dbf34f5adc/`；旧EXE不能与新脚本快照混搭回滚。

## Lua 地产/资金/放置卡继续迁移（2026-10-11）

- 上一轮为实际进展，本轮继续最新架构任务；旧goal仍活跃，不以模块文件数量声称完整协议完成。
- 新增28张Lua编排卡，合计33张：20张地产、3张资金、2张街区、3张地面放置。资金计算/地面参数/成功回包进入Lua，地产合法性与增益生命周期仍用C++核心计划器。
- 核心新增 `property.prepare`、`relations.break`、`map.cell`、`ground.prepare`；`funds.prepare`支持多角色和存款增量。库存、地产、地面、关系和资金在回包完整转换后共同提交。
- 脚本回包转换失败也可在未调用原生/数据库且未提交时400B恢复，日志增加 `lua_card_committed`。未运行实机测试；最新日志仍为45308旧实例。
- C++目标、全部Lua语法编译与差异检查通过，完整迁移边界见 `LUA-SERVER.md`，行为依据见 `evidence/normal-cards/lua-property-funds-ground.md`。
- 确认无服务进程后已更新GUI使用的EXE，SHA256 `B357F98A3E5EF9AC76D693ECC835154F21AC2010882A82452E1AD5AB9205245D`。`build-migration-backup/lua-card-transactions-c8775457f4964758928beee1c39d495b/` 保存旧EXE、新版脚本快照与回执；旧EXE不搭配新版脚本回滚。下面为历史版本记录。

## Lua 业务层（2026-10-11）

- 新增 Lua 5.4 宿主 `richnet_scripting`：脚本快照、每连接独立 VM、内存/指令预算、模块循环检测、受限标准库和错误堆栈均由 EXE 管理。
- 大厅、对局、落点、随机卡池、节日点券、BOSS 攻击许可和商城入口已提供 Lua 事件；原生兼容事务仍是默认回退，确保迁移期间通信协议、库存和资金原子性不变。
- `server/scripts` 已拆出 92 个卡牌模块、地图/BOSS/格子注册表、商城和核心协议工具，每个文件含中文职责说明。控制管道新增 `scripts.reload`，只替换新连接使用的脚本快照。
- Lua 数据库接口为参数化 SQL 批次，禁止事务控制、PRAGMA、ATTACH 和多语句；脚本数据库错误会整体回滚。构建会复制脚本并用 `RichOnline.LuaCompile` 预检查语法。
- 本轮 C++ 主目标与全部 Lua 语法编译、`git diff --check -- server` 通过；不启动服务或游戏、不运行测试，实机通信验证由用户完成。
- 确认服务进程已退出后，已更新 GUI 使用的 `server/RichOnline.Server.exe`，SHA256 `71AFF9074992B384829ACBEED020B1AA8BB9DBDA356BA556730E0477FAE2A5C4`。旧版及回执保存在 `build-migration-backup/lua-runtime-a14b97af1b1a431f991ba57f43162d36/`，脚本位于 `server/scripts`。此次包含此前未安装的请神距离、NPC7和经典建筑改造修复。
- 已完整移入 Lua：乐透及4张视效卡、奖励候选筛选、节日点券表、BOSS攻击选择。其余复杂业务仍在C++兼容层，不能宣称已实现“所有核心接口绑定/所有业务纯Lua”；细节与继续迁移边界见 `LUA-SERVER.md`。
- 卡片格的四张卡限制改为资源允许且已实现的主动卡池；不再因为合法合成产物不在直接赠卡池中而改变抽卡概率。攻击卡拒绝日志增加实际槽位和完整8格手牌，供追查面板/服务端库存差异。
- 圣诞点券仍未闭环：本轮 IDA 实例73d0b204c154复核7BE080/66A970只有赠卡入口，未获得固定点券奖励证据，不猜测数量补账；大厅商城功能请求仍需继续核对实际配置/商品拒绝日志。

## 当前安装状态（2026-10-10）

- GUI 启动路径 `server/RichOnline.Server.exe` 已更新，SHA256：`D859ED0429B93D2ED608E5DC916CECC40A7A85F3E920B68FE446B0E057403B4B`。旧程序备份为 `build-migration-backup/fortune-null-capture-3477e121073b488d906326a19f61b38d/RichOnline.Server.before.exe`（SHA256：`B19A1FD0EE9C6E0C0EE1D069AD976C8BCD0AC6869233B53A67B2AF96E545FE50`），同目录保存candidate.json。更新前确认无服务进程，编译版/安装版哈希一致，未启动服务或游戏；实机验证由用户完成。
- 本版包含福神四来源随机两张卡、成对/随机传送出口地雷、飞弹基地周期齐射、节日赠卡和点券同步修复。客户端现有节日资源没有独立万圣节槽，不能把未确认的日期或奖励硬编码为万圣节。

## 待安装增量：请神距离、糊涂神及经典建筑改造卡（2026-10-10）

- 正式会话接入已有NPC7糊涂神规则及主库存清醒卡/状态免疫保护，13张地图池增加7；附身时长来自服务端Npc副本。地面、请神、倒计时、控制移动和BOSS禁止攻击沿用现有消费者。证据见 `evidence/normal-cards/sleep-deity-production.md`。无神/缺卡/无附身等400B恢复已存在，未重复改动。

- 请神112改为按目标角色格坐标距离最近优先，同距离按格号；NPC候选过滤保留此顺序，不再全图随机。新增成功提交日志 `richonline_summon_selected`。距离政策为针对用户反馈的显式规则，不声称客户端暴露原服排序或视口。证据见 `evidence/normal-cards/summon-nearest.md`。

- 125–129已接通40CD–40D1，改kind2–6、保留产权和等级、与扣卡共同提交；非法请求400B。经典改造保留原增益登记；可再改回BOSS特殊建筑。
- 按客户端单BOSS场景零上限处理经典建筑自有落点，避免负数kind-11索引；建屋卡正等级经典建筑不再误允许升级。BOSS模式不虚构经典租金。
- 证据见 `evidence/normal-cards/classic-conversion.md`；清单当前70项处理、7项未实现。编译和差异检查通过，未新增/运行测试或启动服务/游戏。
- 构建候选 `build/RichOnline.Server.exe` SHA256：`091DA2F613C662569318BC967449855C733389F0394EFAC7C4A26CF20C939410`。检测到服务PID45308，尚未覆盖GUI程序，已询问用户停止服务；安装版仍为顶部记录的福神修复版。

## 已安装增量：请神卡召福神导致服务崩溃（2026-10-10）

- `native-14508.jsonl:353` 在112请求后中断；同秒Windows Application 1000记录PID14508服务异常 `0xc0000005`。福神回调捕获了已被move清空的局部cards，调用随机选卡时解引用空指针。
- 回调改为持有 `rules.cards`；同时修复地面、神庙、福神卡和请神卡四条随机赠卡入口。live IDA核对40C0/4023及恢复操作分支，协议无需改动。证据见 `evidence/normal-cards/fortune-null-capture.md`。
- 编译与差异检查通过，已备份并更新GUI服务程序；未新增/运行测试，未启动服务或游戏。完整通信协议goal继续。

## 当前增量：长城/图腾柱周期增益（2026-10-10）

- 审计发现生产会话没有激活攻防建筑来源；当前倍率计算器并不等于增益功能可用。live IDA确认有序登记、周期、激活等级、持续时间及轮首顺序，见 `evidence/normal-cards/building-buffs.md`。
- 已接入地产唯一权威状态、轮首周期生产、持续时间、战斗快照与原子提交；伤害使用激活等级。当前两角色为对手，1480无队友分享，不把1472同盟卡用于共享增益。来源、等级、持续时间和登记表参与地产版本校验。
- mode3产权变化保留旧登记；换屋按来源地/目标地顺序追加，换地按目标地/来源地顺序。改造删除旧kind首条登记并清对应增益；飞弹降级同时检查两类增益，低于缓存等级才失效。拆屋和街区降级不执行mode4专有的即时清理，避免错误套用飞弹规则。
- live IDA确认初始地产无主、登记容量为type12地产数、mode3剧本事件期间暂停周期及到期。用户明确选择0级不发增益，保留登记待正等级，规则名 `wait-for-positive-level`。原始证据见 `evidence/normal-cards/building-buff-integration-client.json`。
- 目标编译与差异检查通过，未新增/运行测试或启动服务；游戏效果由用户验证。新增 `richonline_building_buff_round` / `richonline_building_buff_activated` 日志。原有战斗测试仍含按当前等级/所有权取倍率和任意受损清增益的旧断言，按用户要求本轮未修改或运行测试；不能引用旧断言作为验证。

## 当前增量：攻击及神明卡入口恢复（2026-10-10）

- 攻击卡109/111/124/133及神明卡112/113/130/131的解析、控制和回合校验统一在纯准备阶段恢复400B，避免入口拒绝向会话层抛出；战斗快照、库存/时钟提交及续接错误仍保留。
- live IDA重新连接至实例 `c57d1bd2171b`，核对400B恢复语义；证据见 `evidence/normal-cards/card-entry-recovery.md`。没有新的游戏复现日志。
- 编译及差异检查通过，备份后更新GUI程序并校验哈希。未新增/运行测试或启动服务；65项处理、12项未实现的卡牌统计不变，完整goal继续。
- 当前13地图descriptor均无投资点67；0x2A投资续接仍是待接能力，不误记为已完成。

## 当前增量：涨价卡1058（2026-10-10）

- 按live IDA补齐119/40C7、同街区涨价标记5和原子扣卡；来源kind8/9/10拒绝。与查封共用有对象/版本约束的街区计划，保留两种独立状态。
- 当前mode3不执行经典模式涨价倒计时或租金，不额外虚构BOSS现金收入。92项清单现为65项处理、12项效果未实现、9项被动、6项本地返回。
- 同轮核对40DF/40F1，客户端重定位后恢复操作，不追加普通落点事件；0x2A是途经投资点暂停，仍需独立接入。证据见 `evidence/normal-cards/price-rise1058.md`。
- 编译及差异检查通过，备份后更新GUI程序并比对SHA256；未新增/运行测试或启动服务。完整协议goal继续。

## 当前增量：改造后0级建筑续接（2026-10-10）

- IDA确认改造卡可按能力0产生保留kind的0级建筑；原改造已接受，但后续战斗/基地计时提交会错误要求kind-1而失败。现仅在正等级实际降到0时要求清空类型，保持未变的0级建筑。
- 证据与源码原因见 `evidence/normal-cards/converted-zero-level.md`。编译及差异检查通过，未新增/运行测试；旧程序已备份，实机由用户验证。
- 基地所有权变更的客户端重复登记语义仍需继续核对，不宣称完整协议goal完成。

## 当前增量：直接神明卡替换强化（2026-10-10）

- 财神1069和福神1070直接用卡替换已有附身时，按live IDA先清除旧神庙正强化，再附新神明；同神明替换也清除。保留原轮盘、随机赠卡和时钟续接。
- 开店1034已确认只接受sprite11，当前BOSS地图地产装载支持sprite12，仍保留拒绝，不能仅写kind1伪装成功。
- 证据及安装清单见 `evidence/normal-cards/direct-god-replacement.md`。编译与差异检查通过，未新增/运行测试，完整goal继续。

## 当前增量：查封卡1035（2026-10-10）

- 已接通C2S100/40B4，脚下同街区所有地产查封计数置5，并原子扣卡。计划拒绝400B，不扣卡；提交失效保留真实错误。
- live IDA确认倒计时及营业限制属于经典地产分支，当前BOSS模式不执行；不擅自暂停BOSS特殊建筑。证据见 `evidence/normal-cards/seal1035.md`。
- 92项清单现为64项处理、13项效果未实现、9项被动、6项本地返回。编译及差异检查通过，未新增/运行测试；开店卡及其他未实现项继续保留门禁。

## 当前增量：研究卡拒绝与提交边界（2026-10-10）

- 1181/1182/1183与大厅39/40均已有会话接入；下文早期未接入说明保留为历史记录。
- 冰冻/火焰/毒气卡请求的阶段、日历等校验失败改为400B恢复，不扣卡、不发送成功包。毒气卡将纯计划拒绝与共享状态提交错误分开，提交失效不再被吞成普通拒绝。
- live IDA与源码证据见 `evidence/normal-cards/research-recovery.md`；编译及差异检查通过，未新增/运行测试，游戏验证由用户完成。

## 当前增量：地面与请神卡 NPC4/6（2026-10-10）

- IDA确认地面4/6附身后继续落点，请神卡40C0附身后恢复操作，无金钱轮盘。已接入共享附身时钟与已有轮首光环账本，并加入13张BOSS地图生成池。
- 替换旧附身时按客户端先卸除旧强化，地面福神奖励同样保留修正后的状态。
- 证据与边界见 `evidence/normal-cards/ground-aura.md`；目标编译与差异检查通过，未新增/运行测试。旧NPC46文档的地面门禁描述已被本轮替代，完整goal仍继续。

## 当前增量：福神随机两张卡（2026-10-10）

- 源码审计发现地面福神、神庙召唤、福神卡及请神卡四路径仍使用固定数组；现生产入口统一绑定随机选择器。第二张依据第一张插入/合成后的背包抽取，用卡来源先考虑扣卡后背包，不提前提交。
- 4023仍按客户端顺序发两个WORD卡号，保留原附身、满手牌及阶段续接。增加选卡日志，随机池沿用当前地图已接入卡牌，两次允许重复。
- live IDA证据及安装信息见 `evidence/normal-cards/fortune-random.md`。目标编译和差异检查通过，未新增/运行测试，游戏验收由用户完成；goal继续。

## 当前增量：飞弹基地自动发射（2026-10-10）

- 日志确认Kid Ken 3-4玩家155号kind12地产已升至5级；原服务端没有基地周期、齐射和4016计时通知。本轮已接入共享地产/战斗事务，并更新GUI候选。
- live IDA确认4016进入轮首phase8，周期取BwbValue的PAO首列；到期先发40BF(flag1)齐射，再发4016推进客户端周期。按等级选择道路/地雷/NPC/敌人并发3–7弹，复用共享伤害、头盔、连锁和破产结算，新增逐轮时钟及发射日志。BOSS控制状态限制保留。
- 证据、原资源规则、明确的随机/空目标策略与安装清单见 `evidence/normal-cards/missile-base.md`。严格目标编译和差异检查通过，不新增或运行测试，客户端效果待用户验证；完整goal继续。

## 当前增量：随机传送目标地雷（2026-10-10）

- 日志定位234到121的随机传送后直接切回合，源码确认目标地雷处理被跳过；live IDA确认4209只更新位置，须补4017引爆。
- 随机传送到普通/超级地雷后，按新位置计算并同步爆炸链、伤害与地雷移除，实际破产才结算；普通走路踩雷保持原响应，避免重复引爆。
- 后续已将28/61成对传送终点接入相同出口地雷处理；IDA确认原动画不会自行触发出口雷，入口4013之后仅补4017，不重复移动或触发出口静态事件。日志补充source格号。传送卡、换位卡和中途传送仍需独立核对；飞弹基地进展见上节。
- 证据、边界及本轮候选哈希见 `evidence/normal-cards/teleport-mine.md`；仅代码、编译和差异检查，未运行测试。
- 编译及差异空白检查通过，不新增或运行测试；当时的候选位于 `build/RichOnline.Server.exe`，后续安装状态见本文顶部。

## 当前增量：节日赠卡与点券同步（2026-10-10）

- 按服务端Feast副本的13个有序节日槽补齐五类赠卡40A0和愚人节40A1，玩家回合开始响应并同步权威手牌或账本，同一天只执行一次。
- 同步元旦111、春节180、端午55、重阳99点券，固定奖励由客户端本地显示，服务端不重复发赠券包。随机扣券按客户端规则最低归零。
- 赠卡复用地图可用卡池及资源组合，满手牌正常继续；同时修复随机卡格在满手牌时抛异常的路径。日志记录奖励卡号或各角色余额变化。
- live IDA协议、原始节日槽与范围见 `evidence/normal-cards/feast-rewards.md`。已同步感恩节清除负面附身与定时炸弹；原资源无独立万圣节条目，不能凭名称推定赠卡日期或奖励。
- 编译和差异空白检查通过，不新增或运行测试。当时的候选位于 `build/RichOnline.Server.exe`，后续安装状态见本文顶部。

## 当前增量：独立资源副本与花园现金同步（2026-10-10）

- 实际导出 28 个运行资源至 `config/resources`（15 KPD、13 EMP），逐文件校验 SHA256，来源及可选 Grant 缺失记录在 manifest。运行不再读取客户端目录。
- 活动 `data/lobby-bootstrap.json` 资源根改为 `../config/resources`，下次启动生效；原配置备份于 `build-migration-backup/resource-copy-fc47bb36af5d40a4a31817edc28cc63f`。
- 新增独立 bootstrap 模板；账号初始化工具改为校验资源副本，无需客户端 EXE 或 tests。GUI 原有启动服务逻辑无需修改，详见 `config/README.md`。
- 按 live IDA 补齐自有空中花园现金恢复的账本同步，等级收益及现金上限来自真实资源，首次建造不恢复；详见 `evidence/normal-cards/garden-cash-sync.md`。
- 仅编译及静态检查，不新增或运行测试。当前运行服务已变为 PID54416，未覆盖或重启；累计协议候选仍在 build 目录，不能当作已安装。

## 当前增量：普通购地装备折扣（2026-10-10）

- 客户端普通落点购地也调用7CF5E0，原服务端只在购地卡路径处理半价。已统一报价供落点询问、玩家确认、BOSS自动购地及购地卡使用；玩家读取实际profile slot2，BOSS读取关卡bossLand，保留严格大于费用的余额门。
- 证据和候选哈希见 `evidence/normal-cards/property-purchase-discount.md`。源码审计发现，不冒充新日志复现；未改变购地卡/地产原始价格或对手收入。
- Release编译和差异空白检查通过，不新增/运行测试。GUI服务PID29592仍运行，重阳节等累计修复也尚未安装，等待用户停服。

## 当前增量：重阳节赠券与商店期限（2026-10-10）

- 重阳节99点券按真实Feast资源和游戏日同步入共享账本，不重复发送客户端本地赠券消息。保留首个匹配节日优先级，按日期防重复，支持跨年对局。
- 冬眠卡日志实际为超时拒绝；统一增加500毫秒商店传输余量。日志还存在后续余额不足，售卡收入本身已入账。证据和边界见 `evidence/normal-cards/chongyang-shop-sync.md`。
- 换地/换屋补客户端同种类、保护建筑与空建筑目标校验，正常拒绝400B、不扣卡。源码已有洗牌152分支，审计表已纠正为63项处理、14项效果未实现。
- 只编译，不新增/运行测试。GUI服务仍运行，候选安装待停服；不要把build目录编译成功当作已更新运行版本。

## 当前增量：购地卡1031（2026-10-10）

- 补齐C2S96的6字节40B0响应；脚下地产转移产权且保留建筑。按实际profile装备slot2计算半价，现金必须严格大于价格，只扣买方现金，与卡片/地产共同提交。
- 证据见`evidence/normal-cards/purchase1031.md`。92项卡牌现为62项处理、15项效果未实现、9项被动、6项本地返回。未实现项仍400B恢复，不能视为全部效果完成。
- 只编译`RichOnline.Server`，未新增/运行测试、未启动服务。安装哈希与备份见`build-migration-backup/purchase1031-candidate.json`。

接手日期：2026-10-09。来源会话：`01a11afc-1837-7ad0-9129-be1f61c8bc32`。

## 当前增量：全部BOSS地图准备与卡牌分支（2026-10-10）

- 开局拒绝证据：`data/logs/native-50540.jsonl:90/98/120`，原因均为`richonline_ground_card_range_policy_invalid`。地面卡策略校验现兼容GUI使用的角色中心视野配置；阿战波、Kid Ken各4张地图补入运行期策略，当前注册的13张BOSS地图均开放。BS_2_*和BS_3_*使用共享模拟策略，专属BOSS机制尚未还原。
- 92项注册入口逐项记录在`evidence/normal-cards/card-dispatch-92.md`：60项会话处理、17项当前模式明确恢复拒绝、9项被动无直接请求、6项本地返回；不等于92种原版效果或游戏验证完成。
- 新增引爆、换位、乐透、同盟、开路、察看、清除、传送、飞吻、陷害处理。抢夺合成BOSS因空背包返回400B且不扣卡。补齐换地/换屋、天使/恶魔/女神、超级地雷和视效卡；恶魔1077消费映射及地产街区字段已修正。
- 陷害使用真实EMP监狱入口/出口、共享raw1495计时；出狱ACK为十进制21（0015），继续当前回合，迟到/重复ACK短期退役。合成BOSS用1800ms动画计时续接。清除清1500冻结、1496停留及1499梦游等，保留1696狂暴免疫。
- 引爆以独立角色中心视野选取地雷根，响应40EF、4017连锁和400B；开路40CA为9字节含10个2bit方向，不移动角色，只清目的格。乐透固定奖励15000为明确模拟器政策。
- 移动状态、固定步数、视效、净空、冬眠、定时炸弹以及NPC卡已补正常计划拒绝恢复；提交失效和状态不同步仍保留真实错误。
- 只编译`RichOnline.Server`，未新增或运行测试、未启动服务。已在确认服务进程停止后备份并安装`server/RichOnline.Server.exe`，SHA256：`52C3287A67F8AD1660F30A83A4A443C294E373C7A3459450E38C8861C61454EE`。
- 安装记录：`build-migration-backup/boss-map-card-dispatch-5702a9d4950a460bbd2ff78bf72148ad/installation.json`。实机验证由用户从GUI启动后完成。

## 目录与同步

- 后续源码、测试和服务端工具统一维护在 `F:/大富翁online/Richonline/server`。
- 旧源码：`F:/大富翁online/native-server`。本轮按 SHA256 比对，同步 16 个新增/变更文件，保留当前项目的 CMake 客户端资源路径适配及依赖说明。
- 原文件备份和同步哈希清单：`build-migration-backup/sync-manifest.json`。旧目录不删除，也不继续回写。
- 未复制旧构建缓存、临时数据库、测试 EXE 和下载缓存。构建目录为 `build`；源码构建不依赖旧 `native-server`。
- 新版资源位于当前项目根。旧版回归资源及 oracle 仍在父目录，通过 `RICHONLINE_LEGACY_CLIENT_DIR` 显式指定，避免误用新版同名文件。

## 已接续的开发

此前 wave25 的双/三骰与金豆扣费、战斗配置、随机商店与卡片格、研究所选择和产出、红黄蓝事件筛选均已包含在当前源码。

新增研究卡 1181–1183 的独立规划器、动画回报状态机和大厅投票组件已纳入严格编译；前两者的独立测试纳入 CTest。它们仍不等于完整会话接入，尤其不能据此宣称高级研究卡已可用。

黑贝贝 1-2、1-4 的地图配置和真实加密 GameService TCP 长回合测试已纳入 CMake。1-3 独立资源和策略已同步，但其对手预建寺庙（kind16）落点未闭合，继续禁用。

赵灵儿旧目录的启用改动在本轮加密长回合测试中复现失败：第二局 calendar16，人类 C2S0011 报告位置165（关联地产198），服务端以 `richonline_boss_landing_unsupported` 断开。此前同次运行第一局完成149个回合并正常结算，证明一次成功不能覆盖该缺口。当前保留独立资源/策略并恢复禁用；其 CTest 验证资源及生产入口拒绝，不声称全局可玩。失败日志保存在 `build/migration-tests.log`，原始 trace/SQLite 在 `build/scenario-evidence/zhao_scenarios`。

## 验证与证据

- 全新严格构建：`build/migration-final-build.log`。
- 最终全套 CTest：`build/migration-final-tests.log`，202/202通过，70.13秒。
- 已将通过验证的构建复制到 `server/RichOnline.Server.exe`；SHA256：`B648B3A87172A105966CCCF9463CCD1CC23D824328C606EBE92900BEFDCDB63B`。旧目标EXE备份为 `build-migration-backup/RichOnline.Server.before-sync.exe`。未启动或替换旧运行目录服务。
- 早期失败保留在 `build/migration-focused-before.log`、`build/migration-integration-build.log`、`build/migration-tests.log`。
- 测试配置：`tests/fixtures/gameplay-bootstrap.json`，从旧 wave25 候选配置复制，仅修正相对资源路径。它是显式模拟器策略的测试夹具，不是生产部署声明。
- 当前构建及测试不涉及真实客户端 UI；未修改旧在线数据库或管理器启动配置。

## Goal 模式协议进展：对手神庙无效果分支

- 已按 NEW7C6640、7D70A0 和新版 BwbValue 的 MI 字段补齐对手 kind16 的无附身、无召唤落点。当前资源等级1–4可完成，实际召唤与附身分支仍保留门禁。
- 黑贝贝1-3道路164/地产149、赵灵儿道路165/地产198，均加入真人和Boss访客的真实加密TCP固定落点回归。地图生产入口仍禁用，不能据此声明整图可玩。
- NPC地面附身提交前新增投影状态预检；后续地产拒绝时不消耗地面NPC、不提交奖励/金额/附身时钟。单元与回合引擎测试覆盖回滚及重试。
- 严格构建 `build/protocol-temple-build.log`；全套 `build/protocol-temple-tests.log`，202/202通过，64.03秒。证据与协议边界见 `evidence/temple-no-effect/README.md`。
- 已刷新当前目录候选 `RichOnline.Server.exe`，SHA256：`7A57D0FF92C6300A71A48F3C7CC18E030E40086405B3D121CBB9EAC49AB3A9AA`。上一候选备份为 `build-migration-backup/RichOnline.Server.before-temple.exe`；未部署到旧运行目录。
- 附身分支已核对NEW跳板及实际函数，见 `evidence/temple-no-effect/ATTACHED-NEXT.md`。减天数分支还会额外执行一次带符号字节递减，不能只减配置值；当前NPC时钟只接受正值，接入前需用准备/提交事务同步状态和时钟。

## 继续任务

前一增量：对手神庙附身时钟已接入生产回合协调层（具备NPC能力时）。支持当前资源等级1–5对既有NPC0/1/2/3/7的延长、缩短或脱离；保持原始有符号字节算术与同回合幂等。

- 单元测试覆盖资源字段、延长上限、缩短时额外递减、字节溢出、待转盘拒绝、过期事务和重复提交。
- 两个真实地图固定落点 × 真人/Boss × 无NPC及NPC0/1/3，共16个加密TCP场景，验证初始化刷出、地面附身、真人转盘/奖励、神庙续接及最终权威时钟。
- `build/protocol-temple-attached-build.log`严格构建通过；`build/protocol-temple-attached-tests.log`全套202/202通过，54.72秒。NEW GValue加载器及天数操作证据：`evidence/temple-no-effect/attached-clock-evidence.json`；合同更新在同目录`ATTACHED-NEXT.md`。
- 当前候选`RichOnline.Server.exe`已刷新，SHA256：`6BA405CC850D20CBB2CAFE94297FF803D1BC8F86FB4B7FDFC57AF0CF3AEDEE0D`；上一候选备份`build-migration-backup/RichOnline.Server.before-temple-attached.exe`。未部署到旧运行目录。

最新增量：已补齐自有神庙的既有附身效果，区分首次建造403D（直接phase6）与升级403E（接受/拒绝均续接建筑效果），并修复受控角色跳过自有神庙效果的问题。效果按实际升级后的等级规划；待升级保存落点状态，超时取消仍执行原等级效果。无附身且可能进入5级召唤的落点在任何地产变更前拒绝。

- 37个固定神庙加密TCP场景覆盖自有/对手、真人/Boss、地面附身、升级接受/取消/Boss自动升级，以及权威时钟。严格构建`build/protocol-own-temple-build.log`、全套测试`build/protocol-own-temple-tests.log`均通过，202/202，60.73秒。
- 新版IDA证据与合同：`evidence/temple-no-effect/OWN-TEMPLE.md`。实际NPC4/6召唤及效果仍未闭合，黑贝贝1-3和赵灵儿入口继续禁用。
- 当前候选`RichOnline.Server.exe` SHA256：`A00BC15DD500EDD190E45DA92E82C027B44555C91CC9B22374B9BAF2E1206FC2`。上一候选备份`build-migration-backup/RichOnline.Server.before-own-temple.exe`；未部署到旧运行目录。

1. 神庙NPC4/6基础召唤和回合金额效果已接入（见下节）；继续经两张禁用地图的独立长回合验证决定是否恢复入口，正值强化分支仍门禁。
2. 将1181–1183研究卡规划器接入当前回合、背包、地面物、状态时钟和破产结算；毒卡房间计数与多角色原子提交仍需证据和实现。
3. 将大厅39/40嵌套投票组件接入房间成员、超时、换图/踢人和广播；补真实加密会话测试。
4. 完善地图进度字段、剩余卡片、其他地图和多人模式；保持未知业务字段与显式模拟策略的边界。
5. 验证完成后单独记录候选EXE哈希和实际部署状态，用户负责实机UI验收。

完整历史验收合同与证据仍在 `F:/大富翁online/protocol-analysis/richonline-rebuild/coverage/GOAL.md`。本次迁移不代表该合同全部完成。相关历史专项：`coverage/heibeibei-scenarios/README.md`、`game/research-cards-1181-1183/CONTRACT.md`、`game/special-landings/static58-continuation/FINDINGS.md`。

## NPC4/6神庙召唤和回合金额效果

- 已接通自有5级NPC4、对手5级NPC6召唤；准备/提交事务保留角色回合身份，拒绝过期或重复提交。地面刷神与请神卡没有因此开放NPC4/6。
- 回合开始先执行附身到期，再按地图坐标方形范围结算。基数GValue15=800，半径GValue24=2；Boss仅可作为来源，不接受范围金额效果。原始住院/坐牢/绑架字段决定目标资格。
- NPC6扣现金再扣不足的存款；客户端实际以现金归零判破产，即使存款尚存也走现有终局流程。金额批量提交共享账本，不发送额外伪造金额协议。
- 纠正逆向字段：1740是神庙强化值，不是倒计时；当前资源等级1–5强化值为0，正值分支继续拒绝。未复用战斗倍率。证据与边界：`evidence/temple-no-effect/NPC46.md`、`npc46-aura-evidence.json`、`npc46-strength-field.json`。
- 新增范围规划器测试、NPC事务测试、32组回合引擎组合，以及10个真实加密TCP场景；固定神庙TCP共47场，覆盖真人/Boss、两张地图、自有/对手、升级接受/取消与迟到重放。
- 严格构建`build/protocol-npc-aura-final-build.log`；全套`build/protocol-npc-aura-final-tests.log`通过203/203，57.72秒。随后仅调整长对局测试对重叠固定步数效果的跟踪，单独复验记录于`build/protocol-npc-aura-dice-status-tests.log`。
- 旧长对局测试偶发误判：4096固定步数事件生效时仍要求三骰收费。已按实际事件和角色回合递减跟踪，继续核对协议骰数、费用及SQLite扣费。失败证据保留`build/protocol-npc-aura-dice-fixture-failure.log`。
- 当前构建候选SHA256：`80900F2B50DB1442978A88B2420BC9C3B51D09A465F0724CBA58273BF7F2DC15`。候选复制及上一EXE备份见`build-migration-backup/npc-aura-candidate.json`；不代表旧在线服务部署。
- 黑贝贝1-3、赵灵儿生产入口仍禁用；尚未完成它们的新增长对局验收或实机UI验收。研究1181–1183和大厅39/40会话接入仍为后续goal任务。

## 冰冻卡1181通信闭环

- 已接入155→40EB原子扣卡/放置、NPC25落点消耗与冻结、静态事件跳过、地产续接及冻结后的回合恢复。只有真实地图CARD/EMP资格与共享状态能力齐备时开放；毒卡1182（请求156）和火焰卡1183（请求157）仍明确拒绝效果请求。
- 冰冻计数取GValue13=3，人类和mode3 Boss均生效；路过不触发，下一自身回合先递减，跳过两次后恢复。保持NPC附身时钟；不额外发送效果包，也不增加ACK。合法阶段无效研究卡请求返回400B；旧calendar/阶段错误仍拒绝。
- 新增`tests/richonline_ice_turns_tests.cpp`，覆盖加密会话与真实GameService TCP、静态银行/机会/票券落点、真实地产、神明到期、无效请求、原子预检失败和重试。IDA证据与能力边界见`evidence/research-ice/README.md`。
- 严格构建`build/protocol-ice-final-build.log`通过；最终全套`build/protocol-ice-final-tests.log`通过204/204，61.89秒；`git diff --check -- server`通过。未进行实机UI验证。
- 当前候选EXE SHA256：`550DDED364DD924690BEA5D52FF172B1EF547863823DEA8A4F5866393193AC53`。上一候选备份`build-migration-backup/RichOnline.Server.before-ice.exe`；复制清单`build-migration-backup/ice-candidate.json`。没有部署到旧运行目录。
- 下一步：火焰1183落点伤害及独立地面时钟、毒1182房间计数及共享战斗结算、大厅39/40投票接入；goal保持进行中。

## 火焰卡1183通信闭环

- 已接入157→40ED原子扣卡及范围放置，NPC26伤害取真实资源2000并套用共享攻击/防御修正。落点不移除火焰，不发送额外扣款或效果包；相等总余额也判破产，4013后由现有终局协调器接续。
- 火焰GValue27=3按放置者自身回合递减，无主/失活owner按轮锚；独立于401E地雷时钟。冻结回合也计时；路过不触发，空范围仍消费卡片。实际火焰能力要求地图资格、战斗桥接、地面物、背包、预检及终局依赖完整。
- 战斗桥接新增无副作用准备、存活续接预检及共享账本CAS；失败保持原资金与地面状态。回归覆盖修正后1670伤害、余额相等破产、自伤/无主/失活来源、预检失败、human/Boss及地面持续存在。研究陷阱夹具新增真实加密TCP连续踩中与到期验证；毒1182仍拒绝。
- 新版客户端函数、输入哈希及实现边界记录在`evidence/research-fire/README.md`和`fire-new-decompile.json`。严格构建`build/protocol-fire-final-build.log`通过；全套`build/protocol-fire-final-tests.log`通过204/204，62.76秒；差异空白检查通过。
- 当前候选EXE SHA256：`8A1C3DE6E6FE22E5FCC33BE89775502083183F0175B57B1CF181DE8DD0EE3FCB`。上一候选`build-migration-backup/RichOnline.Server.before-fire.exe`，清单`fire-candidate.json`。未部署旧运行目录，也未完成实机UI验收。
- 下一步核对毒卡game+60的初始/复位来源，接入递增计数、范围伤害与多角色提交；然后推进大厅投票和禁用地图长对局验收。goal继续。

## 毒卡1182通信闭环

- 已接入156→40EC，共享扣卡、资金、破产与双向角色关系原子提交。每次命中重算当前资金相关装备修正；冻结目标仍可受击，原始住院/坐牢/绑架字段排除目标。失败不增加次数或改写关系。
- NEW客户端game+60在7C0C50入口清零，属于当前行动阶段计数；前三次1倍，第四至六次1.5倍，下一自身回合复位。坐标射线可穿过非道路格，最后筛选道路目标；未把道路连通性误用为射线边界。后续新增同角色阶段重入时也须保持清零语义。
- 证据与边界：`evidence/research-poison/README.md`、`poison-new-decompile.json`。新增共享战斗事务、实时装备修正、四连发及下一回合复位、旧calendar拒绝、精确余额破产和真实加密TCP回归；三张研究卡均有会话接入。
- 严格构建`build/protocol-poison-final-build.log`通过；全套`build/protocol-poison-final-tests.log`通过204/204，57.12秒。候选SHA256：`CD342C4680BD6F5D10F5604A85DAA9D5521884DE5684ACFD76DA4203D70F9B06`；旧候选备份`build-migration-backup/RichOnline.Server.before-poison.exe`，清单`poison-candidate.json`。未部署旧运行目录，未进行实机UI验收。
- 下一步继续大厅39/40投票的房间成员、超时及结果应用闭环，然后推进禁用地图的独立长对局验收。goal保持进行中。

## 竞技赵灵儿开局与切换频道故障

- 用户报告两项现网故障后优先修复：旧运行日志`native-17772.jsonl`明确记录竞技2的`richonline_map_package_runtime_incomplete`，以及两次C2S8未实现后直接断开。对应CoreDump均在客户端89FD01调用已释放子对象（EDX=dddddddd）时崩溃；现场没有发送16。详细证据见`evidence/channel-switch/README.md`。
- 当前源码已有C2S8清理并返回空16，新增真实LobbyRuntime TCP回归：退房14/57后在频道0/竞技2来回切换，保留认证、正确更新在线成员和房间列表。旧运行EXE哈希A3CE3E37…与当前候选不同，必须更新运行版本才生效；未修改旧运行目录。
- 赵灵儿独立长局在研究升级5→6后复现`richonline_combat_session_building_invalid`断线。修正共享战斗状态、攻击降级输入和降级结果的等级边界为资源模型0..7，新增6/7级不攻击/飞弹/核弹/安全核弹回归并继续拒绝8级。先复现失败，再通过相同回归。
- `V_BS_1_1.emp`现已开放runtime，仍标记partial。竞技2真实provider及加密TCP三局验收覆盖普通/对手地产、研究、Boss攻击、自然终局及正常退出只记账一次。focused通过2/2、48.79秒，三局723回合、37次对手地产；最终全套第二次独立运行也通过。证据见`evidence/zhao-admission/README.md`。按月份到期结算尚未实现，实机UI未验收。
- 严格全构建`build/zhao-channel-final-build.log`通过，全套`build/zhao-channel-final-tests.log`204/204通过、73.00秒。候选`RichOnline.Server.exe` SHA256：`793F75F7F37961B43D6F995A677C28CE32321582A8ACE74BAA32E9641CBDF427`。上一候选备份`build-migration-backup/RichOnline.Server.before-zhao-channel.exe`；清单`zhao-channel-candidate.json`。尚未部署在线服务。
- goal保持进行中：大厅投票、黑贝贝1-3独立长局验收，以及月份终局契约仍需继续。

## GUI 迁移与当前目录启动（2026-10-10）

- 用户要求先恢复 GUI 启动。已将旧 `F:/大富翁online/admin` 的 WinForms 源码迁至 `server/admin`，适配 server 同目录布局及客户端根目录兼容入口，增加自包含构建安装工具和显式账号迁移工具。
- 原根目录 GUI 配置指向旧 `local-server/runtime/native-boss-live-20261009/RichOnline.Server.channels.exe`；现两个入口均指向当前 `server/RichOnline.Server.exe`、`server/data`。原 EXE/配置备份在 `build-migration-backup/admin-d1e4e150eb6a4df094714fad00828769`。
- 通过服务端只读 SQLite backup 迁入 26 个账号，15 张原有表逐行一致，`integrity_check=ok`；未改写旧数据。采用当前已验证三频道 gameplay 配置并重定位客户端资源，客户端哈希保持已验证值。
- GUI 严格发布通过；真实 WinForms 消息循环与按钮回归通过：启动、状态与 PID、四类监听、账号及设置读取、停止、重启、关闭窗体清理。独立空库控制接口自测覆盖账号创建、小数余额、冲突、配置 revision、在线备份、停止及客户端 KPD 参数。证据见 `evidence/admin-gui/README.md`。
- 本次没有重建或覆盖尚未验收的大堂投票增量；GUI 使用已通过 204/204 测试的赵灵儿/频道修复候选，SHA256 仍为 `793F75F7F37961B43D6F995A677C28CE32321582A8ACE74BAA32E9641CBDF427`。投票接入的工作区改动保留，后续必须完成专门回归后再更新候选。goal仍进行中。

## 大厅39/40投票通信闭环

- 已完成每频道/房间的换图、踢人投票接入。提议者收到75，其余成员收到74，完成或10秒超时收到80；批准后另发26/27。支持非房主提议、投票踢房主后的所有权转移、同频道观察者缓存更新。
- 成员/准备/地图/队伍/角色成功变更作废本轮，失败请求保留；迟到、重复、外人和其他generation投票不能改写已作废状态。取消计数0/0/N是因80缺少取消字段而采用的显式本地策略。协议缺少nonce导致同提议者同类型连续轮次旧40不可区分的限制仍如实记录。
- 新增确定性投票测试及真实加密TCP场景，含无人操作的实际10秒超时；投票批准后仍保留开局资源/runtime门禁。协议反编译、测试范围及边界见`evidence/lobby-vote/README.md`。
- 严格全构建和最终全套205/205通过，65.43秒；日志`build/lobby-vote-final-build.log`、`build/lobby-vote-final-tests.log`。实际客户端投票界面尚未交互验收。
- 已更新GUI指向的`server/RichOnline.Server.exe`，SHA256：`3B381B9F73AECE7F2138D45B02F3A07E8A06B5428E65DB0042D3AF6DA9042777`；上一候选`build-migration-backup/RichOnline.Server.before-lobby-vote.exe`，清单`lobby-vote-candidate.json`。更新时仅GUI运行、没有服务实例；下次GUI启动加载新版，没有触碰旧运行目录。
- goal继续：黑贝贝1-3独立长局验收、月份终局契约、其他未闭合地图/协议仍未完成。

## 黑贝贝1-3独立长局验收

- 删除资源检查后跳过BS_1_3的测试捷径，先捕获真实provider门禁失败，再启用该地图runtime。保留partial标记；其余章节门禁不变。
- 独立三局真实加密GameService TCP累计544回合、142次Boss攻击、50次对手地产、4次神庙落点、17次研究决定。两局自然结算，一局320回合后0A/4006正常退出；主动退出loss只登记一次，outbox为空。详细资源/协议边界及证据见`evidence/heibeibei13-admission/README.md`。
- 严格全构建通过。全套204/205通过（112.02秒），唯一失败为误改的BS_3_1传送测试门禁断言；恢复原断言后补验1/1通过。205项均有通过结果，原失败保留在`build/heibeibei13-final-tests.log`，补验`build/heibeibei13-portal-tests.log`。
- 当前GUI候选SHA256：`0DB9D9B8B1029F4DF187510D9F4C0CD7555FCC43E1FBA5F934206378A8A92D68`；备份`build-migration-backup/RichOnline.Server.before-heibeibei13.exe`。更新时无服务实例，不涉及在线重启或旧目录覆盖。
- goal继续：月份到期终局、其他BOSS章节、剩余实际网络请求与游戏分支仍需实现及验证；用户实机UI验收与服务端自动测试分开记录。

## GUI 当前候选复验与待修回归

- server及根目录GUI入口均通过真实WinForms消息循环/按钮自测，读取26个迁入账号，确认当前server/data、PID/实例及六类监听就绪，停止/重启/关闭清理正常。最新证据见`evidence/admin-gui/README.md`。
- 全构建成功；完整独立回归`build/heibeibei13-confirmed-tests.log`为204/205通过、199.28秒。黑贝贝1-3长局及恢复的传送门断言均通过，但赵灵儿长局calendar35的Boss落点165报`richonline_boss_landing_unsupported`并断开；原trace保留在`build/scenario-evidence/zhao_scenarios/V_BS_1_1.emp.trace.jsonl`。
- 此失败尚未定位并修复，当前候选不能声称完整205/205通过。GUI恢复已验收，玩法问题继续纳入通信协议goal，不替换或撤销其他会话改动。

## 赵灵儿神庙6/7级修复与GUI重新验收

- 上节失败已定位为无附身Boss自有神庙5升6的召唤预检：位置166、投影等级6、NPC3。固定回归先红后绿；没有删除原失败记录。已将6级福/衰神和7级财/穷神接入既有奖励、背包、账本、附身时钟与phase6续接，避免再次执行地产/升级。正值强化继续门禁。
- 扩充NPC事务和两地图真实加密TCP回归，覆盖human/Boss、友方/敌方、升级接受/取消/重放、转盘超时、金额失败和破产。详细证据见`evidence/temple-no-effect/HIGHER-SUMMONS.md`；临时stderr已移除，调试journal仅删除本服务端章节。
- 严格构建成功，完整CTest `build/temple-high-final-tests.log` 205/205通过、247.90秒；黑贝贝长局114.46秒、赵灵儿长局48.67秒。差异空白检查通过。
- 当前`server/RichOnline.Server.exe`已更新，SHA256：`F36926A48D0999CE78F925C0BD47D8846CAF4276AA09C91ADBED5951FD9771B3`。安装清单`build-migration-backup/temple-high-candidate.json`，上版备份`build-migration-backup/temple-high-298c046be93e4ec89164cab1e48a7f9c/RichOnline.Server.before.exe`。替换时没有服务实例，未改写旧运行目录。
- 更新后二个GUI入口再次通过真实WinForms消息循环和按钮自测：`build/gui-temple-high-server/gui-result.json`、`build/gui-temple-high-root/gui-result.json`均`ok:true`。读取26账号，当前server/data及六类监听就绪，启停、同库重启和关闭清理通过。保留用户已打开的管理器窗口；未进行真实游戏客户端UI验收。
- Goal仍进行中：月份到期终局、其他BOSS章节、神庙正值强化及剩余未闭合分支还需继续。

## 路障提前停止与衰神减半修复

- `data/logs/native-8544.jsonl`确认路障放置成功，移动回报因`richonline_boss_endpoint_mismatch`断开。IDA的7F5D90确认客户端在NPC11处提前移除路障并发送0011。服务端改为校验到首个路障的路线前缀，保留4011完整骰子和方向覆盖，落点后继续正常处理；路障放置也取消误继承的BOSS距离限制。
- 衰神原先按配置上限最多扣四张，未计算一半。现按实际卡牌张数向下取半，受地图上限及4024四个槽位约束；两张只扣一张，未使用槽位填-1。
- 用户明确调整开发流程：后续只做日志分析、IDA协议核对、代码修改及编译，不新增或运行自动测试；游戏内测试由用户完成。本候选在此指令前的针对性检查已通过，此后只编译及安装，不执行全套或GUI自测。
- `cmake --build server/build --target RichOnline.Server`成功；GUI使用的`server/RichOnline.Server.exe`已更新为`B2D767A7A8A66A0A5F316590AAA3B4D3B4CA35D14DE38C17F06BB67B9A4A6DDC`。安装时没有服务进程，旧程序已备份，清单`build-migration-backup/roadblock-half-candidate.json`。真实客户端玩法验收待用户完成。

## 拆屋卡与怪兽卡

- 根据当前源码缺失分支和live IDA协议补齐101/1036/40B5拆屋卡、102/1037/40B6怪兽卡。前者按请求中的地产编号减一级，后者从当前道路格映射地产减五级；建筑归零置kind-1，保留所有权。两者与背包消耗共用现有地产准备/提交机制，非法目标返回400B且不扣卡。协议依据见`evidence/normal-cards/README.md`。
- 严格编译成功，不新增或运行测试。GUI候选已更新为`B1EDDA64AC9D57A1E47806A5FF85EF4D6126D4C86D820C6E23F7A47D455999FE`；清单`build-migration-backup/destruction-cards-candidate.json`。安装时无服务进程，游戏内效果待用户验证，goal继续。

## 一步卡与六步卡

- `data/logs/native-20428.jsonl:304-306,1128-1130`确认141/136正常八字节请求因缺失处理分支进入`richonline_boss_action_out_of_phase`并断开。live IDA核对136/1079/40D8、141/1084/40DD的角色目标、免疫及状态清除规则，已接入现有状态卡流程。对自己使用接续一/六步4011移动，对其他角色按GValue[18]设置后续固定步数；路线准备成功后才扣卡和提交状态。
- 冰冻卡实机日志另确认`richonline_research_trap_visibility`拒绝。已移除人类地面卡授权中的额外曼哈顿半径，冰冻、香蕉和火焰沿用客户端选格及各自的道路/占用/静态合法性规则；地雷和路障原已不受BOSS距离限制。旧配置保持兼容，BOSS攻击范围不变。
- 编译成功，不新增或运行测试。用户停止服务后已安装`server/RichOnline.Server.exe`，SHA256：`3E91AE20DAECF930DF0C0152327017C41FB0C02E073941DABC006EFBEC130F43`；备份`build-migration-backup/one-six-ground-8057ce8611164b2d8a3ec1568dbab6d8`，清单`build-migration-backup/one-six-step-candidate.json`。未启动服务，游戏内验证由用户完成。

## 全 BOSS 地图开局及卡牌分支审计（2026-10-10）

- 修正可选择地图与运行时开放状态不一致，13 张注册 BOSS 地图均接入开局资源和运行配置。BS_2_*、BS_3_* 使用共享 BOSS 模拟策略，专属机制尚未还原；BS_2_2 从最大道路连通分量选择随机出生点。
- 修正 GUI 配置与服务端校验的兼容问题，包括旧曼哈顿范围、新可视范围和地面卡授权配置，避免正常配置在启动时被拒绝。
- 已逐项记录 92 个卡牌注册入口：60 项当前会话处理、17 项经典地产/股票/洗牌请求明确 400B 恢复且不扣卡、9 项被动卡、6 项本地返回。显式拒绝不等于原版效果已实现；完整范围见 `evidence/normal-cards/card-dispatch-92.md`。
- 上一安装版本 SHA256 为 `52C3287A67F8AD1660F30A83A4A443C294E373C7A3459450E38C8861C61454EE`。本轮只编译，不新增或运行测试，未启动服务。

## 月份到期终局（2026-10-10）

- IDA 核对客户端日历按整轮推进、首次锚点计第 1 天、期限为月份乘 30 的无符号字节值，并在已过天数严格大于期限时停止普通操作。4004 的计数字段属于动作计数，不用来推算天数。
- 服务端新增独立月份终局原因，在下一 BOSS 回合的状态效果及攻击之前进入原持久化结算。无破产槽位，不伪造淘汰消息。未完成挑战按失败结算是显式模拟器政策，不能宣称为原版服务端逻辑。证据见 `evidence/month-limit/README.md`。
- Release 服务端编译成功；候选 SHA256：`12F3FD27E35E2B46C883BB03084BD697735FB78C60AF84E791E1228C2378CA3C`。安装记录以 `build-migration-backup/month-limit-candidate.json` 为准。未新增或运行测试，未启动服务，游戏验证由用户完成。goal 保持进行中，专属 BOSS 机制和经典模式卡牌效果等仍有未实现部分。

## 新开放地图的57类兑换格（2026-10-10）

- 静态审计发现BS_3_1、BS_3_2所含57类兑换格的独立模块未接入BOSS会话，正常落点和地面物件预检都会落入未支持分支；不是新日志中的实机复现。后续读取EMP更正本条最初误列的BS_2_2，该图没有57格。
- 重新通过IDA核对7C54B0：玩家以25点券兑换2000现金，点券不足跳过；合成BOSS直接获得2000现金。已把既有兑换会话接入共享账本、原始脚本状态、落点和NPC/地雷预检，只发4013，避免本地效果重复加钱。
- Release服务端编译成功，未新增或运行测试，未启动服务。证据见 `evidence/merchant57-session.md`，安装清单见 `build-migration-backup/merchant57-candidate.json`。51/54奖励格、58事件格及专属BOSS机制继续推进，不能将开局开放等同完整落点支持。

## 专用奖励格51/54及共享分流（2026-10-10）

- 当前资源确认BS_2_1毒气格、BS_2_2骰子格，原会话只识别8/41/42。已补43定时炸弹、51毒气、53火焰、54骰子四类，正常玩家4013→4029奖励、合成BOSS跳过、NPC/地雷预检共用奖励格分类；沿用原卡包插入、满包和合成规则。
- 固定奖励分别1045/1182/1183/1038，地图资格由真实EMP卡牌表验证。固定主题奖励属于明示模拟器策略，不宣称还原原版掉落概率。协议、资源和边界见 `evidence/normal-cards/static-rewards.md`。
- Release服务端编译成功，未新增或运行测试，未启动服务；安装清单 `build-migration-backup/static-rewards-candidate.json`。58乱传格已定位4209移动回复，但目标选择和续接尚未接入，goal继续。

## 58乱传格（2026-10-10）

- 将BS_2_2与BS_3_1至3_4的58格接入传送落点及NPC/地雷预检。重新通过IDA核对4209→67C080、606C位置写入、动画26清理和朝向保留。正常序列4013→4209→下一回合4010，目的地不重复触发落点，已发送的4013不重发。
- 明示目标政策为全图其他非孤立道路格均匀选择，允许跨越道路连通区域；原版概率尚未还原。脚本事件或睡神/梦游/冰冻时跳过，预检不消耗随机数。详细证据见 `evidence/random-teleport58.md`。
- Release服务端编译成功，不新增/运行测试、不启动服务。安装清单 `build-migration-backup/random-teleport58-candidate.json`。goal继续，专属BOSS机制和其他未闭合效果不因本次落点接入而视为完成。

## 均贫卡1052实际效果（2026-10-10）

- 重新通过IDA核对655030的8字节115请求及670330的40C3回复，将均贫卡从统一拒绝分支接入实际处理。双方现金向下取平均，保持存款/点券，按客户端条件清同盟；卡包和账本原子提交。无至少1元钳制，奇数余数舍弃；32位总和溢出则400B恢复、不扣卡。
- 当前92项注册入口计61项处理、16项暂未实现、9项被动、6项本地返回。未修改默认卡牌分发和模式资格。统一拒绝原因由模式禁止改为实现缺失，见 `evidence/normal-cards/equal-poor1052.md`。
- Release编译通过，不新增/运行测试、不启动服务；安装清单 `build-migration-backup/equal-poor1052-candidate.json`。购地卡折扣字段等仍待补齐，goal继续。
