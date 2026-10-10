# 梦游 BOSS 新闻与星光环绕奖励池修复

日期：2026-10-11。依据用户本轮实测反馈修正规则；只修改服务端和编译，不新增或运行测试，不操作服务/客户端进程。

## 梦游新闻

- 原实现有四处共同阻止新闻：`boss_turns.cpp` 在受控状态下不调用新闻；`chance_landing.cpp` 再次拒绝梦游；`landing.cpp` 将三色新闻当成普通受控静态格直接跳过；`boss_session.cpp` 的 NPC 后续落点预检不接受梦游新闻。
- 新增统一 `richonline_news_landing_allowed`，模式 3、新闻类型 68/69/70、合成 BOSS 梦游时允许新闻；睡神附身和冻结仍拒绝，玩家梦游行为不在本次变更范围。普通卡片格、银行、商店等仍使用原受控状态规则。
- 新闻事务沿用原有颜色候选、资金/状态准备、4013 后 4096 及路口续接；不清除梦游、不虚构 BOSS 手牌。BOSS 的卡片奖励类新闻仍按既有无手牌能力规则排除。
- `richonline_chance_completed` 增加 synthetic_actor/sleepwalking，便于下次实际游玩核对。
- 本轮只读核对客户端 `7C54B0`：其本地特殊格处理受控制状态影响，68/69/70 本身返回等待服务端的分支。这不足以证明原服务器在梦游时的新闻抽取规则；本次例外明确来自用户要求，不能把此修改描述成已完整还原原服。

## 随机奖励池

- 星光环绕资源编号 1131，原 `card_1131.lua` 错误开启 reward_enabled；改为 false，已有卡的使用入口保留。
- `RichonlineBossCards::configure_tile_rewards` 额外过滤 1131 和此前已禁止的 500–519 商城金豆卡，确保无 Lua 的配置回退也不会重新混入。
- 卡片格、福神及共享此候选池的随机新闻均使用过滤后的候选；未修改局内售价或强制回收已有手牌。`shop.cpp` 对未定价卡仍返回 sale_card_unpriced 并保留手牌。
- 脚本目录与安装版共享，但候选池在创建对局时确定；已开启对局不会因此重抽或删除卡片。

## 交付状态

- `cmake --build server/build-goal-resume --target RichOnline.Server -j 4` 成功，包含 Lua 脚本构建；本次修改文件的 git diff --check 通过。
- 候选 EXE SHA256：`A3FEBB169BEBB07B4D3DAC04B8A9A1075ADB5613E2A5B4C3696AA1367BD9701A`。
- 安装 EXE SHA256 仍为 `6234380D32D515FF1A31809C97808254B42F44251C1C6A3B4441577EEF443A6E`；本次未安装候选，未改数据库。运行时效果待用户下一轮验证。
- 前轮装备回血实现继续包含在候选中；装备剩余类型核对及整体 goal 尚未完成。
