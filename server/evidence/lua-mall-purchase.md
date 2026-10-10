# 商城 Lua 购买策略与当前日期限制（2026-10-11）

后续校正：已用客户端证据移除本记录中早先的fold/level一律拒购规则。fold不是商城发货记录数，level在穿戴/使用时检查；详见 `mall-purchase-eligibility.md`。日期兼容限制仍然存在，已生成当前客户端的配套补丁候选，但未部署或迁移运行数据库。

## 最新用户复现

`data/logs/native-54996.jsonl:85` 收到购买选择，`:87` 记录商品1893、item_key5989、currency1、date_epoch2005，拒绝原因为 `inventory_date_year_unrepresentable`。启动记录加载148个Lua模块，仍为original_2005日期配置。拒绝发生在 `purchase_mall_item` 数据库事务之前，本次不会扣款或发货。

已编译 `build-goal-resume/RichOnline.InventoryDatePatch.exe` 与 `RichOnline.InventoryDateMigrate.exe`。现有工具只接受已知客户端映像，生成新补丁副本；迁移工具要求停服并验证客户端后才操作新数据库副本，保留原库和备份。用户测试期间未执行这些工具，也未修改当前客户端、日期配置或数据库。

## 现有日志与代码证据

最新日志 `data/logs/native-45308.jsonl` 第5602行接受C2S16购买选择，5604行的C2S18被`inventory_date_year_unrepresentable`拒绝。启动日志声明纪元2005。`richonline_inventory_date.cpp`使用4位年份差，允许纪元至纪元+15；2005版本无法表示2026年的限时商品。

`data/lobby-bootstrap.json`仍配置original_2005，未给出已部署日期兼容客户端标识。本轮不修改客户端、不迁移现有数据库、不捏造永久期限；不能把此次策略迁移称为商城购物已修复或已开放。

## 实现

- 新增带中文注释的`mall/purchase.lua`，正式商城服务调用`mall.purchase_policy`。商品目录仍来自服务器资源副本，并先经过上架/启用/币种核验。
- Lua决定套装、等级资格，并通过`mall.calendar_expiry`计算真实日历期限；按部署纪元检查可表示年份。C++复核期限与资源一致，之后才执行库存日期编码和原有SQLite扣款/发货/收据事务。
- 策略阶段没有DB副作用。拒绝保留既有错误响应，脚本异常明确拒绝，不静默fallback。只有Lua运行时未启用时才走旧原生资格逻辑。
- 购买/激活原有余额刷新顺序不变：购买profile7先于77，激活213先于profile7。原有同session序列号/收据约束不变，不声称C2S18拥有协议不存在的客户端幂等nonce。
- 商城日志增加商品编号、完整物品键、币种、日期纪元，便于进一步查明具体商品失败；没有启动新服务验证日志输出。

## 验证边界

仅编译C++与全部Lua语法，并执行`git diff --check -- server`。按用户要求不新增/运行测试，不启动服务或游戏。激活流程仍在原生层，套装与等级限制仍未闭环，2026购物需要客户端和数据库的日期兼容配套。
