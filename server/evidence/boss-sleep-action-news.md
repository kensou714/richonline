# BOSS受控梦游：禁止攻击，正常触发新闻

用户再次明确：BOSS梦游期间不攻击，但踩中新闻格仍触发新闻。
本轮找到两处不同门禁：`richonline_combat_action_allowed`原先只检查sleepwalking/frozen，
没有检查睡神附身`possession==7`；`richonline_news_landing_allowed`虽允许合成BOSS的
sleepwalking，却无条件排除possession7。两条已知受控梦游路径行为不一致。
睡神7不是用户此前纠正的随机转向幽灵。身份及受控移动依据沿用
`boss-behavior.md`、`controlled-dice*.md`以及npc/受控回合已有实现，不改NPC编号。

攻击核心现同时拒绝梦游计时、睡神附身和冰冻，覆盖主动武器及BOSS飞弹基地；
回合层的火焰、负面附身地雷爆发和常规攻击在C++先检查相同门禁，Lua不能放宽它。
三色新闻68/69/70单独允许合成BOSS的两种梦游来源，仍拒绝冰冻及真人受控新闻。
既有地雷被踩爆、定时炸弹到期和火焰寿命不是BOSS主动施放，本轮不改变这些时钟。

静态核对落点路径：controlled-static判断→news_allowed→原生chance/Lua tile.news.prepare，
最终共用prepare_richonline_chance_landing；没有把禁止攻击扩散成跳过全部落点。
本轮不新增/运行测试、不启动服务或游戏、不部署/重启线上。只做静态审阅和编译。
