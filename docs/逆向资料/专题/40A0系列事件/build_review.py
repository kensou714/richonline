"""人工结论与逐函数原证配对；没有把自动导出数量转换为完成数量。"""
from pathlib import Path
from collections import Counter
import json

BASE = Path(__file__).resolve().parent
raw_files = ['handlers.json','helpers.json','consumers.json','ui_and_slots.json','ui_callbacks.json']
notes = {}
def group(addresses, status, conclusion, unknown='完整外部依赖与运行行为未验证'):
    for va in addresses.split():
        notes[hex(int(va, 16))] = (status, conclusion, unknown)

group('66a970', '局部语义已审阅', '40A0身份门、N循环、signed WORD结果、即时卡片添加、6063/UI4/608A顺序；RTC文本128B。')
group('66ac20', '局部语义已审阅', '40A1每槽BYTE分支、6062固定41、镜头和提示顺序；末尾当前槽访问无局部核界。')
group('66af10', '局部语义已审阅', '40A2 signed WORD首索引、每槽signed余数轮转、四存款分支及保留48分支；实际表第五项600。')
group('7f0730 7f0750 7f0770', '局部语义已审阅', '注册桥cdecl(G,record)，ECX及栈参数转交thiscall，retn无立即数。')
group('63e5b0 64fa50', '复用已审阅', '基础对象与分派队列head/288B按值ABI及返回游标，本次保存字节，未重新展开插入器。')
group('64f710', '复用已审阅', 'WORD GmsvID与G+0x14784核对，失败MessageBox后返回false。')
group('63e410', '复用已审阅', '读取DWORD[P+1464]位置，记录只留低16位。')
group('63e7d0', '局部语义已审阅', '读BYTE[G+3632+i]有效槽标志；IDA自动隐藏类型错误。')
group('63e1c0', '局部语义已审阅', '返回this+112名称地址；该入口不复制字符串、不检查角色槽。')
group('63e210', '局部语义已审阅', '返回this+1628地图子对象地址；不分配独立地图对象。')
group('63f730 693830 6937d0', '局部语义已审阅', '分别只写首WORD6063/608A/6005，未赋值区不能叫清零。')
group('6932b0', '局部语义已审阅', '6003构造清+4/+5/+6和+8/+12/+16/+20，不写+2及填充+3/+7。')
group('694460', '局部语义已审阅', '6062构造写头并清+3/+4，+2/+6由调用者填。')
group('693320', '局部语义已审阅', '6060构造写头并清+3至+6，+2/+8由调用者填。')
group('694430', '局部语义已审阅', '按真实this写DWORD[市场子对象+284]，本入口ECX=G+0xCD0。')
group('6279c0', '局部语义已审阅', 'A766C8为零时分配0x6C0字节并调用6E2A70构造；返回该界面管理单例，异常尾块释放未完成构造的分配。')
group('627b60', '局部语义已审阅', 'A766DC为零时分配0xC字节并调用6D7170构造；返回文本容器单例，异常尾块释放未完成构造的分配。')
group('627c20', '局部语义已审阅', 'A766E0为零时分配0x14C字节并调用7FEA80构造；返回卡片配置单例，异常尾块释放未完成构造的分配。')
group('693370', '局部语义已审阅', '返回DWORD[this]+1128*id+660的卡名地址；thiscall/retn4，无本地索引检查或文本复制。')
group('629d90', '局部语义已审阅', '返回DWORD[this+8]+DWORD[this]*id的文本记录地址；thiscall/retn4，无本地索引检查或文本复制。')
group('7f8780', '部分分析', '八个六字节槽首空写编号/数量，合成调用与本地UI刷新、P+1416返回覆盖已读。', '合成资格、全卡片配置和UI刷新虚调用尚未闭合')
group('800fd0', '部分分析', '60B启用配方逐条件对八槽计数，命中后清槽并写输出卡、拼接合成名称。', '输出资格谓词、异常配方和完整配置加载未展开')
group('7fea80', '局部语义已审阅', '卡片配置构造对基础指针/计数及多组指针字段清零，未改成完整解析器。')
group('7fd7a0', '局部语义已审阅', '读P+1416返回标志，不将其非零视为添加成功。')
group('67da40', '局部语义已审阅', '6003显示/关闭/超时/发送数据/等待分流；+20不被本handler读取。')
group('67db90', '复用已审阅', '6005 signed位置交镜头7B6F60，地图对象G+1628。')
group('67fa90', '复用已审阅', '6060加模式+6调用加存款；其余现金/减款分流复用4060与范围效果。')
group('67fc80', '局部语义已审阅', '6062按signed BYTE角色，+3优先加点券，+4减点券，signed WORD数量。')
group('67fd10 7f7670', '局部语义已审阅', '6063写P+388并交P+864精灵；本地槽UI0刷新，完整动画类型未闭合。')
group('7f9d20 7f9d70', '局部语义已审阅', 'P+1512点券加/减及减款负值归零，动画通知参数1/0。')
group('681c40', '局部语义已审阅', '608A构造局部DWORD0并把signed BYTE模式与两个0交7C0C50。')
group('7c0c50', '部分分析', '只审608A模式3入口、G+60清零与case3转入继续分支。', '大函数其余模式及全部外部谓词/网络出口未闭合，不计完整审阅')
group('6e4020 6e3b40', '部分分析', '界面管理器隐藏/显示、创建、虚调用、超时字段与可见标志已读。', '完整层栈、异常创建和所有动态窗口虚调用未闭合')
group('6e4640', '局部语义已审阅', '按132B UI记录找到对象，虚表+16转交数据指针；不进行深拷贝。')
group('6fb680 6faef0', '局部语义已审阅', 'UI30/UI4虚表A25A60/A24610安装；30构造登记编号。')
group('70b700', '局部语义已审阅', 'UI4取得ID1，将数据指针交控件虚表+144，调用根+164。')
group('718de0', '部分分析', 'UI30新闻图片句柄表初始化及四分支1/2/6/14映射子号0/2/5/9，48映射58。', '图集内容及所有句柄拥有关系未闭合')
group('7192f0', '部分分析', 'UI30三DWORD载荷及kind0图片/ID2文本消费；kind1偏移、kind2模式分支已读。', 'kind2完整资源路径和实际控件文本复制未闭合')
group('719290', '部分分析', 'UI30关闭读取ID1句柄并调用图片接口，未把共享句柄调用等同最终销毁。', '底层资源所有权及其它关闭路径未闭合')
group('8e3340', '部分分析', '6032CC实现：写this+348单轴纵向坐标，按边界限制并向关联控件传播，第二参为排除指针。', '完整控件布局传播与绘制刷新依赖未闭合')

functions = {}
sources = {}
for name in raw_files:
    raw = json.loads((BASE/'证据'/name).read_text(encoding='utf-8'))
    for f in raw['functions']:
        functions.setdefault(f['va'], f)
        sources.setdefault(f['va'], []).append('证据/'+name)
assert set(notes) == set(functions), sorted(set(notes) ^ set(functions))
rows = []
for va in sorted(functions, key=lambda x: int(x, 16)):
    f = functions[va]
    status, conclusion, unknown = notes[va]
    rows.append(dict(va=va, name_from_idb=f['name'], review_status=status, conclusion=conclusion,
                     unknown=unknown, evidence=sources[va], note=conclusion,
                     full_dependency_closure=False, outgoing_functions=sorted({c['implementation'] for c in f['calls']})))
counts = Counter(r['review_status'] for r in rows)
(BASE/'function_review.json').write_text(json.dumps(dict(scope='40A0系列静态局部审阅；非全依赖闭环及实机验证',functions=rows),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
lines = ['// ============================================================================', '// 逐函数覆盖与证据分级', '// ============================================================================',
         '// 仅导出不等于已分析；以下由人工结论登记。所有函数保留外部依赖边界。',
         '// 计数：'+'；'.join(f'{k} {v}' for k,v in counts.items()), '//']
for r in rows:
    lines.append('// '+r['va'][2:].upper()+' / '+r['review_status']+' / '+r['conclusion'])
(BASE/'04_逐函数审阅清单.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print(json.dumps({'unique_functions':len(rows),'review_counts':dict(counts)},ensure_ascii=False))
