# 同款商城实例与装备开局修复

2026-10-11。按用户授权完成代码、静态客户端取证、编译和本地离线更新；未启动服务端或客户端，未运行测试。

## 根因

- `native-63712.jsonl:155` 的第二张传送卡在扣款前被 `mall_inventory_conflict` 拒绝。客户端登录 wire2、商城回包 wire77 都逐条建立拥有对象，同一完整键可以重复出现；原表 `PRIMARY KEY(username,encoded_item)` 错把实例键当成唯一键。
- `native-63712.jsonl:239/247/255` 的开局拒绝原因为 `richonline_boss_profile_slots_nonempty`。开局代码曾拒绝除测试证书外的全部装备，因此有效时装也无法进入对局。

## 修复

- `lobby_inventory` 增加 `inventory_id` 自增实例主键和账号/完整键索引。已有旧表在服务端首次正常启动的同一 SQLite 事务中重建并逐行保留；购买、邮件转移、激活、结算回放按实例处理，库存快照保留重复键和购买顺序。
- 激活删除所选旧实例，再追加新实例，匹配客户端激活管理器的“移除首个旧对象、追加新对象”顺序；激活不再因同款副本存在而冲突。
- 开局从 `Prop.kpd` 校验槽位与 `part`，应用已闭合的现金属性；已接入车辆骰子容量/费用选择和攻击/防御属性。宠物、神灯、移动特效、自动回血等仍明确拒绝，避免忽略未实现的局内效果。

## 取证与编译

`mall-instances-equipment-client.json` 保存 23 个客户端函数的伪码及函数块与当前磁盘 PE 的逐块校验，全部匹配；其中包含重复库存、激活追加顺序、装备属性读取和开局相关路径。

`cmake --build server/build-goal-resume --target RichOnline.Server -j 4` 通过，`git diff --check` 通过。候选/已更新服务端 SHA256：`6234380D32D515FF1A31809C97808254B42F44251C1C6A3B4441577EEF443A6E`。

## 更新记录

离线安装脚本 `build-goal-resume/install-mall-equipment.ps1` 已执行成功，备份目录为 `build-migration-backup/mall-equipment-6f09d40c5e904ee4a02c2bf715a15a50/`。本次只替换服务端 EXE 和同代 150 个 Lua 脚本，未改写数据库；数据库实例迁移会在下次服务端启动时完成。服务端和客户端当前均未运行。
