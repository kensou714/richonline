"""将人工审阅结论与原证对应；不是从导出状态推算分析完成。"""
from pathlib import Path
import json
import hashlib
from collections import Counter

BASE = Path(__file__).parent
raw = json.loads((BASE / 'stock_core.json').read_text(encoding='utf-8'))
notes = {}
def group(addresses, status, note):
    for address in addresses.split():
        notes[hex(int(address, 16))] = (status, note)

group('623cb0 623ee0 64f2a0 65d520', '部分分析', '只闭合股票资源/本局初始化/股票UI入口；其余启动和回合分支未完整分析。')
group('6283e0 6c0e50', '部分分析', '独立StockName/StockRace系统初始化边界；回调登记存在，业务协议未展开。')
group('658510 676ba0 677180', '部分分析', '股票选择、认购转移和清仓相关分支已读；道具目标、动画及完整状态闭环未闭合。')
group('7061f0 7f3c70', '部分分析', '只审股票按钮入口/限制检查，或角色十项持股和成本归零；整个函数不计完整分析。')
group('63eca0', '部分分析', '股票能力由两个模式谓词的或值决定；两个底层模式谓词未展开。')
group('80e770 80e6b0 80e710', '部分分析', '本地模拟算法和随机范围已读；没有闭合有效业务调用者，不能用作线上权威定价。')
group('71b2f0', '部分分析', '资源句柄与图片调用已读，未闭合整套绘制器和图集分类语义。')
group('6bf380 693be0', '复用已审阅', '复用移动与动画协议/回合调度专题结论，本次重新保存函数字节；不计新分析。')
group('6e2620 6e2660 6e26a0 6e26e0 6e2710 6e2740 6e2770', '局部语义已审阅', '公共虚调用/声音接口转接，参数按汇编核验；不把声音反馈误称输入锁。')
group('628b50 80dc30 80dc50', '局部语义已审阅', '24字节股票配置单例、指针初始化和释放。')
group('80dca0', '局部语义已审阅', 'STOCK/RANGE字段读取、44字节记录、阈值与无索引检查；公共解析器复用旧专题。')
group('80fb60 80fbd0 80fc00 80fc30 80fc50 80fc70 80fc90 80fcf0', '局部语义已审阅', '配置基础价/总股数/活泼性/涨跌阈值/名称getter。')
group('691940 691960 727d20', '局部语义已审阅', '地图股票数与配置索引表getter，及市场本局条数getter；原IDA库名误识别。')
group('80e0e0 80e100 80fcb0', '局部语义已审阅', '市场条目数组指针初始化/释放及嵌入历史环构造调用；分配器和CRT不展开。')
group('80e170', '局部语义已审阅', '本局配置索引映射、80字节条目、初始价格扰动、阈值及容量61历史环。')
group('692e80 692fa0 692fd0 694ae0 727d40 727da0 728750 7287b0 7287e0 7288c0 7288f0', '局部语义已审阅', '市场限制/价格/持股/涨跌/剩余量/曲线高低值getter或比较，类型及无索引检查已核。')
group('63f650 63f6b0 7f9f10 7fa0a0', '局部语义已审阅', '存款读取、权威覆盖、扣款下限和加款；资源281/286交叉证明资金名称。')
group('7f96f0 7f9760 7f9850 7f9950 7f9a00 7f9b50 7f9cb0 7f9de0 7f9e90 7fdc50 7fdca0', '局部语义已审阅', '买卖/认购/清仓数量、成本、存款与市场剩余量关系；异常浮点转整数运行时边界未闭合。')
group('67aeb0 67af20 67afc0 67b180', '局部语义已审阅', '4200..4203包消费、市场ECX、字段类型、价格历史和UI刷新。')
group('67b350 67b560', '局部语义已审阅', '4204/4205角色选择、数量与成交价格、持仓更新后最终存款覆盖。')
group('67b770', '局部语义已审阅', '4206文本编号、24字节6003提示事件及6080阶段2入队；服务器触发语义未知。')
group('728840 728870', '局部语义已审阅', '0200/0201构造只写消息WORD；后续UI写股票和数量WORD。')
group('6e7180 6e7f00 6e80b0 6faff0 6fb750 6fb810', '局部语义已审阅', 'UI8/32/35对象大小、构造及虚表绑定，与当前磁盘虚表交叉核验。')
group('6effd0 6f0020 6f00c0', '局部语义已审阅', 'UI35回调经界面管理器转发虚表+100/+104/+140。')
group('70cb60 70cbf0 70d0f0', '局部语义已审阅', 'UI8股票和四角色持仓绘制、点击只存选择槽；未直接提交买卖包。')
group('719830 719990 7199d0 719d80 719e60', '局部语义已审阅', 'UI32持仓列表、股票索引控件数据、数量输入/买卖/取消及提示tick。')
group('71b3c0 71b8f0 71c280 71c4c0 71d620 71d950 71de80 71df20', '局部语义已审阅', 'UI35初始化、列表详情、历史图、数量与金额、输入提交/关闭和短暂提示。')
group('80ee70 80ef50 80efd0 80f030 80f0b0 80f130 80f170 80f1f0 80f2d0 80f420', '局部语义已审阅', '行情广播更新、涨跌表示、名称映射、30点历史与60点曲线缓存；指令ECX已抽查。')
group('80fd20 80fdc0 80fe50 80fee0 80ff60 810020 810050', '局部语义已审阅', '价格环形容器容量/满空判断/追加/弹出/遍历；容量61最多保存60项。')

assert set(notes) == {f['va'] for f in raw['functions']}, (set(notes) ^ {f['va'] for f in raw['functions']})
rows = []
for f in raw['functions']:
    status, note = notes[f['va']]
    rows.append(dict(va=f['va'], name_from_idb=f['name'], evidence='证据/stock_core.json',
                     review_status=status, note=note, full_dependency_closure=False,
                     outgoing_functions=sorted({c['implementation'] for c in f['calls']})))
(BASE / 'function_review.json').write_text(json.dumps(dict(
    scope='游戏内股票局部语义审阅；不是全依赖闭环或实机验证', functions=rows),
    ensure_ascii=False, indent=2), encoding='utf-8')
counts = Counter(row['review_status'] for row in rows)
lines = ['// ============================================================================',
         '// 逐函数覆盖与证据分级',
         '// ============================================================================',
         '// A=局部语义已审阅；B=部分分析；R=复用已审阅。全部保留外部依赖边界。',
         '// 已导出不等于全依赖闭环；此表只给出本专题实际读到的职责。',
         '// 计数：' + '；'.join(f'{key} {value}' for key, value in counts.items()),
         '// 原证：证据/stock_core.json；机器清单：证据/function_review.json。', '//']
labels = {'局部语义已审阅': 'A', '部分分析': 'B', '复用已审阅': 'R'}
for row in rows:
    lines.append(f"// {row['va'][2:].upper():8} {labels[row['review_status']]} {row['note']}")
(BASE.parent / '05_逐函数覆盖与分级.txt').write_text('\n'.join(lines)+'\n', encoding='utf-8')
binding = json.loads((BASE / 'stock_binding.json').read_text(encoding='utf-8'))
supplement = json.loads((BASE / 'stock_4206_constructor.json').read_text(encoding='utf-8'))
checks = binding['data_checks'] + binding['registration_checks']
validation = dict(function_count=len(raw['functions']), function_bytes=sum(
    r['size'] for f in raw['functions'] for r in f['byte_ranges']),
    thunk_count=len(raw['thunks']), data_check_count=len(checks),
    function_mismatches=[f['va'] for f in raw['functions'] if not f['bytes_match_disk']],
    thunk_mismatches=[t['va'] for t in raw['thunks'] if not t['matching']],
    data_mismatches=[d['va'] for d in checks if not d['matching']], review_counts=dict(counts),
    core_sha256=hashlib.sha256((BASE / 'stock_core.json').read_bytes()).hexdigest(),
    binding_sha256=hashlib.sha256((BASE / 'stock_binding.json').read_bytes()).hexdigest(),
    supplement_4206=dict(function_count=len(supplement['functions']),
        thunk_count=len(supplement['thunks']),
        function_mismatches=[f['va'] for f in supplement['functions'] if not f['bytes_match_disk']],
        thunk_mismatches=[t['va'] for t in supplement['thunks'] if not t['matching']],
        sha256=hashlib.sha256((BASE / 'stock_4206_constructor.json').read_bytes()).hexdigest(),
        coverage_counted=False))
(BASE / 'validation.json').write_text(json.dumps(validation, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(validation, ensure_ascii=True))
