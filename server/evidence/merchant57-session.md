# 57 类兑换格接入 BOSS 会话（2026-10-10）

## 发现来源

最新服务日志仍是 `data/logs/native-50540.jsonl` 的开局配置拒绝，未新增真实玩家对局记录。本项来自对新增可玩地图与当前落点分发的静态检查，不声称已在游戏内复现或验证。

`BS_3_1.emp`、`BS_3_2.emp` 的地图规格包含 static57。已有 `RichonlineMerchantSession` 和特殊落点规划器，但 `make_richonline_boss_session` 没有创建或调用该会话；其正常落点最终交给只接受普通路和点券格的 balances，NPC/地雷落点预检也会拒绝。后续只读EMP核对更正了本记录最初误列的BS_2_2，该图没有57格。

## 客户端依据

本轮使用 IDA-MCP 的 RnClient.exe 实例 `5c7b48b1123e` 直接重新读取 `7C54B0`：

- case57 的玩家分支先判断点券是否小于 25；不足只显示文本 181，继续原阶段链。
- 点券足够时，本地记录扣除 25 点券并增加 2000 现金。
- 合成 BOSS 分支直接增加 2000 现金，不扣点券。
- 整个 static57 分支最后返回 1，继续地产阶段；没有新增网络请求。
- 该函数入口保留脚本事件、睡神、梦游和冰冻等跳过条件。现有规划器使用同一状态规则和 game+83830 授权。

## 接入

只在地图包含57时创建兑换会话，共享本局账本与现有 game+83830 状态读取器。正常落点进入 `merchant->land`；NPC、地雷等地面效果的落点预检进入 `merchant->validate_landing`。准备阶段不改账本，提交仍由既有 snapshot/revision 检查保护。

发送原有4013，服务端账本同步扣点券/加现金，不另发资金增量，避免客户端本地重复加钱。使用已有 `richonline_merchant_landed` 日志，记录位置、角色、前后现金/点券、脚本状态和结果。

包含地产引用的特殊格仍受原规划器限制；没有把未知地图组合当普通路跳过。51/54奖励格及58事件格仍待另行接入，13张地图已开放开局不等于每个落点均已完成。

## 构建

`cmake --build server/build --config Release --target RichOnline.Server` 成功。按用户要求未添加或运行测试，未启动服务。安装记录见 `build-migration-backup/merchant57-candidate.json`。
