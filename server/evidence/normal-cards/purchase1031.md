# 购地卡1031 / C2S96 / S2C40B0

2026-10-10，IDA-MCP实例5c7b48b1123e，RnClient.exe。静态协议核对，未启动服务或运行游戏测试。

- NEW6528C0发送6字节请求：日历WORD+2、库存槽BYTE+4、组BYTE+5。脚下必须关联地产，非己方所有，建筑种类不得8/9/10。现金严格大于折扣后价格。
- NEW66B610读取脚下地产，经6071转移产权，6060扣当前角色现金，6061消费卡片，6006恢复操作。没有支付旧所有者的记录；保留建筑种类/等级。
- NEW7CF5E0通过60F14E/63F3C0检查actor+152，正数时对价格算术右移一位。已核对63F3C0汇编cmp DWORD[actor+98h],0 / setnle，确为有符号正数检查。
- NEW7F3C70复制272字节人类profile。server_lobby_adapter.cpp的profile_record将equipment[i]写在144+4*i；richonline_boss_host.cpp将同一inventory.equipment传给startup。故actor+152对应slot2，不能由卡片库存、角色等级或BOSS装备推算。
- 会话将该装备条件显式传入回合规则；profile未知时拒绝。当前开局门禁仍仅接受空装备和既有证书，因此当前人类正常全价。

实现使用既有地产PreparedCombat、卡片PreparedConsumption和资金commit_batch。准备阶段校验地图目标、产权、建筑种类、价格有符号范围和余额，提交时一次更新买方现金、产权和卡片。存款/点券及旧所有者余额不变。合法请求返回6字节40B0；非法请求400B恢复操作且不扣卡。

仅编译RichOnline.Server；未新增或运行测试。92项审计现为62处理、15未实现、9被动、6本地返回。未实现分支的400B恢复不等同于原版卡片效果。

下一项洗牌1125已核对：658A20发送6字节，6774E0读取count BYTE+6、从+8复制4*count字节；6811B0清活动且game+3672+slot为0的角色库存，再按每项WORD卡号/BYTE数量/BYTE角色分配。7F8780先插入空槽后可能排序，不能简单回显原库存槽位。暂未修改该卡实现。
