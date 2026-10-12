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
