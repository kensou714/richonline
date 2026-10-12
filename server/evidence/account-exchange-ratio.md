# 代币兑换金豆倍率纠正

用户确认规则：1代币兑换1000金豆；线上实际只得到1金豆。
只读下载当前线上lobby-bootstrap后，按wire30正文+20读取f64，确认为1.0。
当前release为89923befd953，EXE源码97fd5485c5b76129695b7386c8d2b35043a97b89。

## 根因与同步链路

这不是客户端资源问题。`richonline_account_policy`从completion的+20读取倍率；
wire42正文为两个DWORD币种1/2和一个f64代币数量。`Storage::exchange_gold`
在一个SQLite事务内扣coins数量、按amount*ratio增加gold并写两项审计。
wire79返回两个币种、原代币数量和实际金豆增量；客户端8ADA10把金豆增量加到
缓存金豆，再除以同一wire30倍率扣代币。倍率同时驱动两端，不应只把回包乘1000。

线上和默认模板仍保留早期诊断的1:1政策，policy_notes.economy30也明确写着
`divisor48=1 explicitly local 1:1 conversion test policy`。本轮改为用户确认的1000，
保留completion前20字节以及商城、地图、端口等配置。

## 配置发布

`Set-ServerExchangeRatio.ps1`验证预期release、EXE哈希、旧倍率、实际进程/任务，
先归档配置与任务、完成在线数据库备份，再以ExpectedInstance正常停服。
使用File.Replace切换配置，重新启动原任务，检查新实例、监听及
`lobby_bootstrap_policy_loaded.exchange_divisor=1000`。运行二进制无需改变。
启动前失败恢复配置；启动后失败保留证据并报错，不自动覆盖玩家数据库。
已有上线中断授权通过AllowActiveSessions明确传入，不绕过实例和备份检查。

本轮是配置修复，未改C++/Lua逻辑，无需重新编译EXE。已完成PowerShell语法解析
以及JSON二进制字段回读；按用户要求不运行测试或购买/兑换模拟。
运行时验证与本机配置交付在完成后追加。
