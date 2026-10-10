# DENG 出场特效与动画映射准入

2026-10-11。纠正先前把DENG统称“神灯独立回合能力”的判断：当前资源是出场灯光，客户端本地播放一次。仅有万丈光芒1132具有真实映射，不能按Prop中的DENG类型全部放开。

## 客户端证据

- `604F78 → 7D6C50`检查装备槽3（actor DWORD39）有效；7F3C70初始化时将actor1418加1。7F3840初始化该字节为0。
- 回合入口7C0C50检查装备及`600766 → 7D6600`的actor1418正值，然后构造`603ABF → 63F080`的本地6000消息，用`60C5D9 → 7FB1C0`返回的动画号填入子类型，消息长度20字节，排入本地队列，最后`611778 → 7D6630`清零actor1418。
- 该状态只标记一次出场播放；已检查的读写点没有额外扣卡、增益、金币或主动请求。服务端保留原profile槽位并发送既有4010即可，不另造播放包或服务端等待状态。
- `601440 → 7D7A90`取低12位编号，7FB1C0通过`605054 → 640C30`查12字节记录并直接读取+8动画号。缺记录会返回0且调用处未判空，所以不能仅凭Prop存在就准入。
- 623CB0实际加载`Data/ASTable.kpd`，640230解析DENG的prop/wait/anim及MOVE的prop/dir0..3。13个完整函数及交叉引用保存在 `equipment-entrance-client.json`，函数块与安装客户端PE全部匹配。

## 实际资源差异

- Prop中DENG有1132–1135，但ASTable的DENG.num=1：仅1132，wait=other_20_0，anim=34。其余三种不开放。
- Prop中MOVE九种，ASTable也有九条，但并非同一集合：ASTable包含3126而缺3066。因此当前Prop/ASTable交集为1140、1141、1142、1143、1144、1244、1410、1522共八种。
- 此结论补正上一轮 `equipment-move.md` 的九种全部按类型放行；当时尚未读取真实ASTable。3066不得进入客户端无映射路径，3126也不能绕过Prop槽位验证。
- 从客户端只读复制ASTable至 `server/config/resources/Data/ASTable.kpd`，两者SHA256均为 `C5EC090C1677EDF72DF45649BA4E4EA3FF6EB2BD375F1148774F426D6F626C17`。未修改客户端文件。

## 实现

- `RichonlineCombatModifierResources::parse`新增可选appearance文本，复用有大小限制的字段解析器，检查MOVE/DENG计数、顺序行、重复编号、编号范围、四方向/等待资源名和动画号。
- `load`加载ASTable。旧资源目录缺文件时仍可使用其他装备，但MOVE/DENG映射为空，不猜测默认值；资源文件存在但损坏则保留明确解析错误。
- 开局先做原Prop/slot校验，再验证MOVE/DENG实际映射。错误为 `richonline_equipment_visual_resource_missing`。有效1132及八种移动特效解除额外门禁，PET仍保留能力门禁；通用现金、攻防、回血仍走原资源计算。
- `config/runtime-resources.json`新增ASTable交付项，打包时带上这个非图像资源表；未将客户端exe或图像纳入服务端。

## 验证及交付

C++和Lua编译通过，修改范围diff检查通过。未新增/运行测试、未启动/停止服务或游戏。运行中动画展示及实际开局仍待用户验证。

候选 `build-goal-resume/RichOnline.Server.exe` SHA256：`A9DE5EF6BB11108C143E843F81055A1BE6B10C69820D54DA8103CE2E663DA157`。安装EXE仍为 `6234380D32D515FF1A31809C97808254B42F44251C1C6A3B4441577EEF443A6E`，本轮未替换。
