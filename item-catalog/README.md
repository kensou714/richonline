# 大富翁 Online · 游戏资料

双击 `public/index.html`（或本目录“打开道具卡图鉴.cmd”）离线打开。顶部导航可切换八类表格：

| 页面 | 条数 | 内容 |
|---|---:|---|
| 道具卡 | 100 | ID、名字、描述、点券售价、卡片图 |
| 事件 | 900 | 地图事件格、闯关新闻、首领战新闻、适用地图、图像 |
| 角色 | 9 | 名字、性别、生日、口头禅、默认角色图 |
| NPC | 34 | 名字、出现玩法、附身/重生天数、图像 |
| 地图 | 121 | 地图文件编号、名称、说明、地块尺寸、选择界面图片 |
| 商城道具 | 722 | 商城配置中的道具、类别、说明、代币/金豆售价、图像 |
| 音效 | 1128 | 当前生效资源 ID、文件、格式、大小、试听 |
| 背景音乐 | 22 | 当前生效资源 ID、文件、格式、大小、试听 |

超过100条的表格分页展示；手机可左右滑动表格。原生音频播放器按需加载，不自动播放，换页停止播放。

本机预览：在项目根目录执行 `python -m http.server 4173 --bind 127.0.0.1 --directory item-catalog/public`，访问 http://127.0.0.1:4173/ 。可通过 `#cards`、`#events`、`#roles`、`#npcs`、`#maps`、`#mall`、`#sounds`、`#music` 直接打开对应页。尚未发布到公网。

## 重新生成

Windows、Python、Pillow，以及 `resource-manager/native/ResourceCodec.dll` 或项目根目录 `ResourceCodec.dll`。在项目根目录执行：

```powershell
python item-catalog/export_catalog.py
```

导出程序只读游戏资源，写入 `public`。`export_cards.py` 可独立更新旧卡片数据文件；八页网站使用的总数据必须运行 `export_catalog.py` 生成。

## 数据依据与边界

- 道具卡来自 `Data/Prop.kpd` 的全部 CARD 记录；`saleG` 为商店出售许可、`priceG` 为点券价格。不显示未许可渠道的占位数字为真实售价。原图按 icon → `Tex/card.dat` → npid 对应文件读取首帧；89条有图，85张独立PNG。515～518缺原图，1080～1083、1126、1128、1129未设置icon。
- 商城来自 `Data/SellProp.kpd` 的722个唯一道具ID，保留738条原始售卖条目作为依据。结合 enable、saleLJ/saleLR 与售价，分别显示代币、金豆；未开放购买的配置明确标注。币种名称依据 RichStr 580/581/587/588，不能直接使用旧编辑器对字段的猜测标签。
- 角色来自 `Data/Role.kpd`，图片通过 suit0 关联 `Tex/role.dat` 的首帧。部分口头禅在原始文件已写成问号，显示方框并注明原文缺字，JSON保留原始值。
- NPC 来自 `Data/Npc.kpd` 与 `Tex/npc.dat`；天数非正值显示“—”，不擅自解释为周期。
- 地图收录当前 `Map/*.emp` 的121份文件，含不同版本/变体，不等同于大厅全部可选择地图。名称与说明直接读取文件头，73张预览按 `MapView.kpd` 的选择界面图片关联；其余48条无配置预览，显示暂无图片。
- 事件含 `Tex/event.dat` 的地图格类别以及 `KoNews.kpd` / `BwNews.kpd` 新闻行。资料编号由类别/源行号形成，非网络事件ID。新闻的数值范围和卡片参数来自同一原始行；原文与字段完整保留。
- 音频按包号连续扫描、首包批次过滤、后包同ID覆盖前包的游戏规则，导出当前生效WAV/MP3；JSON保留覆盖链。不将资源包编号当曲目ID，不猜测无名称曲目的场景用途。

`public/catalog.json` 保留原始文本、来源映射、文件SHA-256与缺图记录。`catalog.js` 提供相同数据用于离线加载。发布只需完整复制 `public/`，包含 images/ 与 audio/。

## 验证

先启动预览服务器，再从项目根目录运行 `node item-catalog/qa.mjs`。脚本使用本机 Codex 的 omowright 与独立无头 Chrome 配置，迁移机器需调整 import 和 Chrome 路径。当前证据在 `test-artifacts/catalog/`；旧 table/ 与其他截图属于历史布局。
