# 2026-10-11 本地商城配套安装

用户明确授权客户端日期补丁、库存数据库迁移副本及配置配套更新，并要求“你先更新，我再测试”。本次只更新本地GUI所用路径，没有操作远程服务器或GitHub。

- 客户端：`F:/大富翁online/Richonline/RnClient.exe`，SHA256 `FEEEAC1BF9605690E8A774452456320125D7D3DBAA2DC73D529F8230C0677BC7`。保留此前客户端修改，仅三处日期纪元字节变化；安装后专用验证工具通过。
- 服务端：`server/RichOnline.Server.exe`，SHA256 `F9124C7EFCFD6CBB73F8E2DD0E72C8BC7031C8A0DCAD6E27D50540FB3C62737C`。包含立即移动卡Lua迁移、商城购买条件修正、账号装备请求/保存/通知。
- 150个Lua源文件逐项与该构建的scripts副本相符；安装回执保存完整清单。
- 数据库：`server/data/richonline.sqlite3`，日期元数据`richonline-inventory-date-2021-v1`；配置`inventory_date_version=compat_2021_v1`，兼容标识一致。迁移器使用新副本，原库在成功准备后才切换。
- 离线预检无未解决项。账号29、角色29、库存4、装备4、审计174、操作97，迁移前后相同。已有4张测试RP证保持原键，不需要重编码；历史收据保留。
- 原服务端/客户端/数据库/配置，以及与旧服务端匹配的scripts.rollback已保存。备份根：`server/build-migration-backup/mall-datecompat-b3421e7f128343348be0eefd56ddb40f`；`installed.json`是完整安装回执，数据库旁的`.datemigration.json`保存迁移审计。

第一次安装在首个File.Replace前因PowerShell将空backup参数转换为空字符串失败，没有切换任何目标；改成明确原文件备份路径后重试成功。安装后只读核对实际数据库与配置，未启动服务或客户端、未运行测试。实机购物和装备体验仍待用户测试；完整goal保持进行中。

回退必须成套恢复客户端、服务端、数据库、配置及匹配脚本。用户开始新一轮测试并写入数据后，不能无条件覆盖旧数据库，否则会丢失新数据。
