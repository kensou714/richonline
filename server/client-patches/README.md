# 客户端补丁发布目录

客户端变更统一交付到本目录，每次使用独立版本子目录，保留历史版本。
子目录中的客户端资源和发布ZIP为本地交付，不提交到公开Git仓库。

当前商城补丁：`89923befd953-boss-mall/`。

- `BossChest-Mall-Client.zip`：可直接发布的补丁压缩包。
- `Data/`：按客户端相对路径排列的修改文件；本次只有Prop.kpd、SellProp.kpd。
- `changed-files.txt`：改动用途、原版/新版SHA256及字节数。
- `changed-files.json`：相同清单的机器可读版本。
- `catalog.csv`：本次商品、售价、期限和定价依据。
- `README.txt`：安装说明。退出客户端，备份旧文件，再覆盖包内Data目录。

后续补丁也保留相对路径、变更清单和发布包；不把账号库、日志、部署配置放入客户端补丁。
运行中的客户端不自动覆盖，不把生成补丁等同于已经安装。

商城生成工具默认在本目录创建带UTC时间的版本子目录；也可以显式指定：

```powershell
python -X utf8 server/tools/Build-BossChestMall.py --client-root . --output server/client-patches/版本-boss-mall
```
