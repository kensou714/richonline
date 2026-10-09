# 服务端开发交接

接手日期：2026-10-09。来源会话：`01a11afc-1837-7ad0-9129-be1f61c8bc32`。

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
