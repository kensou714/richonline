# RichOnline 官网

ASP.NET Core 8 自包含 Windows 程序，网站源码仅放在 server/website。首页、注册、修改密码、自助领取代币与 item-catalog 共用一个 HTTPS 来源。无支付或审核流程。

## 账号规则

- 注册：4～20位 ASCII 字母/数字/下划线；8～32位可兼容游戏的新密码。遵守原生服务的 registration_enabled 配置，角色初始资金沿用原设置。
- 修改密码：验证账号与原密码；密码散列沿用游戏既有 scrypt 实现，不建立第二套账号数据库。
- 领取：查询本账号角色，按所选角色实时 coins 检查。余额 <10000 时 **增加10000**，余额 >=10000 拒绝。金币/金豆不变。每次申请32位随机操作ID，同一账号/角色重复提交返回原流水。
- 账号认证、余额检查、资金写入及审计都在游戏服务同一锁和 SQLite 写事务内。网站只使用4条固定本机命令，不代理通用管理管道，也不直接改游戏数据库。
- 游戏中的余额显示需重新登录刷新；网站不伪造大厅资产同步。

## 构建与配置

`tools/Publish-Website.ps1` 接收 Output、CatalogRoot（原 item-catalog/public）和 SourceCommit，从固定源码快照编译，自包含运行时一并发布。catalog 是发布时复制的私有资源，不纳入 Git；发布副本去掉独立index.html/styles.css，/catalog/与首页、账号页都使用wwwroot/index.html，资料数据脚本与图片音频按需加载。源码不含证书、真实账号或运行数据库。

运行目录 website.json（在服务器生成，不发布示例凭证）包含：PublicOrigin、BindAddress、StateDirectory、CertificateFile、PrivateKeyFile、PipeName、SourceCommit。PublicOrigin 必须为 HTTPS 来源。生产初始来源 `https://103.156.25.81:18743`，管道 `richonline-production`，进程必须与游戏服务使用同一 Windows 账号。

网页使用 Secure/HttpOnly/SameSite=Strict 防伪造Cookie、CSRF令牌、严格Origin和Host、CSP、输入长度、请求速率和管道并发限制。密码不记录日志，不进入URL和浏览器持久存储。修改密码不是遗忘密码找回。

## 部署

1. 原生服务编译加入 storage_website.cpp，先按既有 richonline-release 流程备份数据库并部署；未完成商城卡候选不混入。
2. Prepare-WebsiteTls.ps1 只为现有 nginx HTTP 虚拟主机添加 ACME challenge 静态目录，保留其余请求原重定向，先备份、检查语法再reload。80/443继续由原 nginx使用。
3. lego v5.5.2（官方发布校验和验证）申请 Let's Encrypt shortlived IP证书。私钥只保存在服务器限制ACL的 acme目录。
4. Install-Website.ps1 验证所有发布文件，单独创建 RichOnline-Website任务和18743防火墙规则。新站启动失败恢复原网站任务；不动游戏进程。
5. 证书每天04:30检查续期，证书变更时仅重启网站任务，游戏不重启。日常运维应检查 RichOnline-Website-Certificate 的 LastTaskResult 和证书有效期。
6. 原生 bootstrap network.website_url 指向PublicOrigin；旧商城储值、注册、首页地址HTTP302跳转。两个服务器列表HTTP路径保持原响应。客户端连接补丁只改KPD的网页URL，不改游戏连接字段或EXE。

## 验证限制

按用户要求仅静态检查与Release编译，不新增/运行测试，不启动本机服务或游戏。部署就绪与证书读取检查不代替用户的账号实测、页面视觉验收或完整玩法验证。
