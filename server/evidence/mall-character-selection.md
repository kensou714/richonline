# 商城切换角色断线（2026-10-11）

## 运行证据

`data/logs/native-52272.jsonl` 第65–95行：

- 2026-10-10 22:18:42 UTC，连接3已完成角色确认 NEW34→NEW70 和频道进入 NEW7，收到频道资料 NEW9、272字节玩家资料 NEW7 等。
- 中间没有创建/加入房间请求。22:18:46.454 UTC，客户端从商城切换角色，发送 NEW10、4字节模型编号。
- 服务端报告 `richonline_request_rejected wire_type=10 reason=richonline_room_peer_not_in_room`，随后异常经 `scripts/network.lobby` 传播，关闭连接。

这是把合法频道操作错误限制到房间内造成的断线，发生在持久化角色模型之前。日志没有输出模型编号内容，不能推断用户选择的是哪一个角色。

## 修复

`RichonlineRoomDirectory::select_character` 原先无条件调用 `room_for_peer`；改为查询可选的房间归属。

- 已注册频道、未入房的玩家可以切换模型，继续由原有 `Storage::select_model` 验证账号角色归属、事务保存与审计。
- 角色模型仍限制0–8。实际存在房间时，继续禁止准备中或游戏中的切换；有房间才取消房间投票。
- 成功仍广播已有 NEW18 `{actor, character}`，并更新频道缓存 NEW7 的模型字段。后来加入频道的观察者及后续开局可以读到新模型。
- 不更换账号角色ID、账号库存、装备键或钱包，不创建房间，不额外发送商城购买响应。

## 交付

- Release C++及151个Lua模块语法编译通过；`git diff --check`通过。按用户约束未新增/运行测试、未启动或停止服务及客户端。
- 本地离线更新成功，候选与已安装 `RichOnline.Server.exe` SHA256均为：
  `A975E10FAAF14DC37E02120AE8912B57C637C854D5479407D08831BAF7DB272F`。
- 安装器逐个验证151个源码/构建Lua文件一致；此版本一并包含先前土地核爆保护及日志、梦游BOSS新闻、随机奖励可出售过滤、装备回血与MOVE/DENG映射修复。PET仍未开放。
- 备份及回执：`build-migration-backup/gameplay-fixes-b7b886352fe54de9b00521e62c75f323/installed.json`。
- 数据库原文件哈希在安装前后相同；仅离线复制备份，未迁移或改写玩家数据。服务端与客户端均由用户自行启动和实测。

此前备份过程中用户重启曾导致数据库占用而退出；那次未替换EXE。以本次成功回执为准，不能把中断的备份目录当成完整安装备份。
