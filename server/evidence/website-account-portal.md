# 官网与自助账号服务

## 用户确定的规则
2026-10-12：整合 item-catalog 作为官网资料站；提供账号注册、修改密码和代币申请。玩家输入游戏账号密码，所选角色余额低于10000时每次增加10000，无需审核、无需支付。先使用服务器IP，客户端改动集中放server/client-patches。

## 实现范围
- 账号操作通过本机管理管道固定 website.register/account/password/claim 四条命令进入现有Storage。复用游戏账号、密码散列、默认角色配置，不直接从网站连接SQLite。
- 领取以角色归属认证、事务内实时余额、操作ID审计回执实现原子检查与幂等重试；不把金币/金豆误当代币，不接受客户端传金额。
- 静态官网＋ASP.NET Core自包含宿主，18743端口HTTPS。资料站完整public在打包时复制，保留八种分类、图片和音频；复制后导航增加官网入口，原资料站源文件不变。
- 旧18680 HTTP网页路径按network.website_url返回302，原有两个频道列表路径维持不变。
- online.kpd原文证实reg/cong/wang/news字段；没有独立改密URL字段，改密由官网统一导航提供。补丁仅改四个网页键，不改EXE及连接端点。

## 编译与边界
官网.NET首轮Release自包含编译退出0，原生服务独立tree 9149bb3e46dc39b8ddfdbf2ef494f43f8241e724 的Release目标编译退出0。未新增/运行测试、未启动本机服务或游戏。网页视觉和真实注册/改密/领取仍由用户实测，不宣称已验收。

未混入尚未完成的商城卡背包消耗候选；当前storage.hpp中的商城方法声明不属于本次发布快照。

## HTTPS
使用验证过官方校验和的lego v5.5.2，获取Let's Encrypt的IP shortlived证书。仅在原nginx HTTP默认虚拟主机添加ACME challenge例外，其他路径仍保持原重定向；证书和ACME账号私钥限制ACL且不入库。80/443未替换为游戏官网。
服务器PowerShell5对无BOM中文脚本的解析曾导致预检查失败，配置未写入；改UTF-8 BOM后预检查、nginx配置检查与签发成功。

## 实际发布结果

2026-10-12完成提交、推送与部署：

- 原生账号接口：`e4acf83e416a9990f088039c31abae0ebd39a716`，线上release `e4acf83e416a`，PID9796，instance `9796-138935253075800`。EXE SHA256 `BC35F73189A2BA5A604622DCCA850B556F2B69F729868D866E3F21D20707E9B0`；214文件逐一核对哈希和长度一致，179 Lua模块，六类监听ready=true，gameReady=false仍保留未完成玩法的能力边界。
- 官网最终源码：`c769aaaa2f1a4d42ee447c8cc14ecf50996bab20`，release `c769aaaa2f1a`，PID5532，2170发布文件核对一致。原生服务与网站独立发布，网站后续修正无需重启游戏。
- 网站地址：`https://103.156.25.81:18743`。首页、注册、改密、领取、资料站、资料JSON脚本、地图PNG及官网CSS/JS公网只读访问均200；`/catalog`正确跳转到`/catalog/`。
- 首次网站版本证书链未显式送出，后续`bfcca8145b374bd83cf63bec8f611f4e656c71f0`补齐；最终Python使用certifi受信任CA集合、保持验证开启后通过，Windows默认TLS验证也通过。本机Python默认证书库存缺少相应根证书的失败不再误算成服务端漏链。
- `c769aaaa2f1a`同时修正ASP.NET将资料站有/无尾斜线识别为相同路由的冲突。最终.NET Release编译退出0。
- 原生18600/18602/18604/18605/18606/18680及官网18743公网TCP可达；两个服务器列表HTTP200。旧`/MEMBER/LoginForms.asp`及`/gameinfo/index-gameinfo-10.aspx`返回302到官网register/claim。
- 网站任务Running；证书续期任务Ready，首次计划`2026-10-13 04:30:30 +08:00`；当前证书有效至`2026-10-18 16:26:30 UTC`。仅配置续期任务，未宣称未来续期实测通过。
- 预发布数据库备份：`D:\richonline\shared\data\backups\accounts-1791768600678100.sqlite3`。配置/原任务备份：`D:\richonline\backups\20261012013000-website-preflight-e4acf83e416a`。确认原生配置只变资源根目录及新增website_url，1:1000兑换及商城配置保留。安装器另有正常备份与ExpectedInstance停服。
- 本机原生EXE确认无运行进程后备份并替换为相同SHA；未启动本机服务或游戏。
- 客户端补丁：`server/client-patches/e4acf83e416a-website/RichOnline-Website-Client.zip`，SHA256 `e6c69d3d0619fe77687838b18331ec9a722c0b28046e4ae76f9bf990b7e87cc4`。该目录含overlay、变更说明和manifest；现用客户端未直接覆盖。

发布依据在私有`server/build-website/`保存，包括固定源码tree、构建日志、包清单、公网就绪结果及服务器核验脚本。无新增/执行测试，无账号注册、改密或领取变更探测；真实账号流程与视觉仍待用户实测。

## 官网与资料页共用模板（2026-10-12）

用户要求资料页与主站共用一套页面，并参考旧游戏官网的信息组织。浏览器实际读取大宇旧站 `http://richol.softstar.com.tw/gameinfo/index-gameinfo-3.aspx`：游戏简介、股票、房地产、操作、会员等级、奇迹技能栏目仍可读；截图显示红黄背景、白色正文与失效Flash区域。采用其玩法资料入口思路和暖色方向，不复制历史活动、不冒称像素复刻。

- 首页、账号页与 `/catalog/` 统一读取 `wwwroot/index.html`；资料八类导航处于主站导航下，复用页脚、宽度和颜色令牌。移除发布副本独立的catalog/index.html和styles.css；旧index地址跳转至统一入口。
- 保留原资料数据、图片、音频、分页和hash分类。资料脚本仅在资料路由加载，首页和账号页不加载1.2MB数据。
- 固定tree `0e6d76e9299d5d6dd019cabc3ddc3a3995f28767` Release自包含编译退出0，JS语法、PowerShell解析和diff格式检查通过。未新增/运行测试，未启动本机服务，未执行账号变更或视觉QA。
- 源码 `472f5167d60c33a58a190fe805063b1582462107` 已推送，线上网站release `472f5167d60c`，PID8800，任务Running，2169发布文件哈希/长度全部核验。
- HTTPS证书验证开启：首页、资料页、账号页、脚本/样式/地图PNG均200，旧catalog/index.html跳转成功。首页与资料返回HTML的SHA256相同，证明实际部署读取同一外壳。
- 原生服务仍为 `e4acf83e416a`，PID9796未变；网站独立更新未重启游戏。商城卡片候选没有发布。
- 发布材料在私有server/build-website/unified-*；增量包SHA256 `4a7b98a8d4a581a0a453813d652c57a82d7f6ea34ef06398b6302440ab46afcc`。

## 旧版官网资料研究与页面信息架构（2026-10-12）

浏览器直接读取旧版大宇官网：

- 游戏简介：`http://richol.softstar.com.tw/gameinfo/index-gameinfo-3.aspx`。页面把传统、PK、BOSS 玩法分段介绍，并给出入场费、游戏时间和组队说明。
- 股票系统：`http://richol.softstar.com.tw/gameinfo/index-gameinfo-2.aspx`。正文说明市场总览、单只股票、走势图、买入和卖出界面，以及价格、涨跌、交易量、玩家持有数等字段。
- 房地产系统：`http://richol.softstar.com.tw/gameinfo/index-gameinfo-4.aspx`。正文按住宅区、连锁区、商业区及建筑类型分层，分别描述土地、建筑和费用/专属功能。
- 奇迹技能：`http://richol.softstar.com.tw/gameinfo/index-gameinfo-8.aspx`。说明奇迹须由对应技能开放，技能等级决定建筑等级上限，并列举研发中心、飞弹基地、长城、图腾柱和金字塔等技能。
- 同站导航还列出系统配备、操作介面和会员等级说明三个栏目；这轮未读取其正文，因此新指南不添加无内容的栏目，不编造配置数字、按键或会员权益。旧版大陆官网 `rich.9you.com` 在本次查询中无法解析。

改版采用旧官网“先讲玩法，再分系统说明”的内容顺序，并保留金红框架、金色强调、白色正文与原版小尺寸游戏插画的视觉提示；不复制已失效Flash区域。首页按玩法入口、系统入口、资料图鉴和账号服务组织；`/guide/` 作为统一外壳内的玩法指南，`/catalog/` 仍沿用同一HTML、页眉、页脚与资源分类表。规则说明标明历史版本属性，避免误当成当前服务器保证。

固定改动范围为 `server/website/`（`DESIGN.md`、`Program.cs`、`wwwroot/index.html`、`wwwroot/site.css`、`wwwroot/site.js`）。静态JS检查、Git差异空白检查通过；官网 .NET 8 Windows Release build 退出码0，0警告/0错误。未启动服务、未运行测试或账号流程、未做页面视觉验收。发布结果另以本轮最终记录为准。
