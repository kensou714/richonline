"""保存人工核对结论和分级；导出数量不代替语义审阅。"""
from pathlib import Path
from collections import Counter
import hashlib
import json

BASE=Path(__file__).resolve().parent
PROJECT=BASE.parents[4]
raw=json.loads((BASE/'functions_raw.json').read_text('utf-8'))
notes={
'0x9208a0':('局部语义已审阅','取得当前CRT存储块，直接把32位Seed写+20；种子0没有特殊处理。','存储块由930960提供；不把该状态称作全进程全局随机种子。'),
'0x9208c0':('局部语义已审阅','从CRT块+20读取state，低32位乘214013并加2531011，写回；逻辑右移16并与0x7FFF返回。','没有系统熵源、没有网络输入、没有在本函数加锁。'),
'0x930940':('局部语义已审阅','初始化CRT块+84为A69ED8、+20种子为1。','A69ED8具体运行库表语义未展开；这不是完整0x8C结构恢复。'),
'0x930960':('局部语义已审阅','保存GetLastError；间接FLS/TLS get，空时calloc_dbg(1,0x8C)，设置槽后initptd，+0线程ID、+4=-1；分配/设置失败amsg_exit(16)。正常返回恢复LastError。','间接函数指针由930760选择，不能只凭名字固定为FLS；终止处理和分配器内部未审。'),
'0x930750':('局部语义已审阅','__crtTlsAlloc包装只调用TlsAlloc；不使用传入FLS callback，retn4清理参数。','TLS回退本身不提供FLS自动回调语义；线程退出清理链需另核。'),
'0x930760':('局部语义已审阅','先mtinitlocks，动态查询kernel32四个Fls API；FlsGetValue缺失时选择TLS四入口。分配槽及0x8C块、设置成功后initptd与线程字段；失败走mtterm返回0。','只在GetModuleHandleA成功分支进行FLS缺失回退；不能声称所有异常API环境都有完整兜底。'),
'0x930d40':('局部语义已审阅','索引不是-1时，以实参或当前槽值调用_freefls，再把当前槽置空；索引-1时不操作。','_freefls外部多字段资源清理未在本专题完整审阅；不能把它描述成只清随机种子。'),
'0x695040':('局部语义已审阅','读取入口ECX对象+0 DWORD，供7ECA40作为元素数量。','该getter本身无范围检查；完整容器类型名未恢复。'),
'0x695010':('局部语义已审阅','读取[对象+12]为数据指针，按index*2加载AX；retn4。','上半EAX非返回契约；7ECA40明确movsx EAX,AX取得有符号short。'),
'0x7d83d0':('局部语义已审阅','先rand，再以机器32位b-a+1作有符号IDIV除数，返回a+余数；不检查倒序、宽度溢出或零除。','外部仅一个未声明函数调用点7B2CBB；本批没有证明实机传入非法边界。'),
'0x7e1420':('局部语义已审阅','保存ECX对象；rand经IDIV[对象+156]取余，读取[对象+160]+4*余数的DWORD。','未确认数组元素业务类型；不证明调用者保证count>0和数组有效。'),
'0x7eca40':('局部语义已审阅','rand后以this+0x45C的count getter取除数；同一成员按余数索引读word，movsx为有符号short。','本函数没有count=0保护、没有检查数据指针、没有过滤负short值。'),
'0x7e20a0':('局部语义已审阅','入口ECX保存为this；最多执行有符号arg0次取样；前4过滤调用用this，第5用[this]作ECX；均看AL。全通过返回样本，否则到上限返回-1。','本包装与取样器未显式移除元素；过滤器不改集合时可重复取样，外部副作用未闭合。过滤业务、完整this类及集合初始化未闭合。'),
'0x623ad0':('部分分析','只核启动播种局部：623AD5 time(NULL)后623ADE srand(EAX)。','后续IME、文字与输出器初始化引用事件文字记录器专题；不在此重复完成整个启动语义。'),
'0x911ab0':('部分分析','只核WM_INITDIALOG分支随机定位：time播种，rand分别取模父窗口尺寸减计算出的目标对话框宽高，再叠加父左上坐标给MoveWindow。目标宽高ACC41C+4388/+4384来自非客户区差值加布局虚表+32返回尺寸。','整个对话框类/提交结果未闭合；余量为0时函数内无IDIV保护，但未证明实机可触发。'),
'0x913e90':('部分分析','只核输入后显示随机串：914090 time播种，按this+400真实文本长度生成rand%62字母数字串；发0xCC设置*掩码，再0x0C写显示文本。','原文字仍在this+400；不把随机显示串误记为加密密码、挑战码或认证协议。其余按键处理未完整审阅。'),
'0x914220':('部分分析','只核另一输入处理尾部同样time播种、按真实文本长度生成62字符表随机串，更新显示控件。','保存入口ECX的EBP在优化汇编中是对象基址；其余按键/焦点行为不宣称已完整闭合。'),
'0x9157f0':('部分分析','只核布局中的time播种及两处rand%16+10，结果作slot+36布局调用的宽度参数；Lower/Upper两组控件。','大函数完整原证已导出，但构造/容器增长/异常清理和整套界面语义未逐函数群闭合。'),
'0x6aa530':('复用已有审阅','复用游戏时间与计时调度：timeGetTime播种，再按分支容器count取模选择。','此专题补状态耦合边界；不增加既有函数审阅数。'),
'0x80e6b0':('复用已有审阅','复用股票与交易流程：float(rand%601-300)/100；本批补32768输出集合的取模基数。','不宣称线上权威定价；二进制浮点不能保证每个百分之一精确表示。'),
'0x80e710':('复用已有审阅','复用股票与交易流程：float(rand%1401-700)/100；本批补映射偏差。','有效业务调用者仍依原专题边界，不套用到服务端行情。'),
'0x81f950':('复用已有审阅','复用音频系统：音乐初始化成功路径81FA75 timeGetTime，81FA83重播种。','同一CRT存储槽内会重置其它消费者序列；是否同线程/同fiber执行未由静态图确认。'),
}
rows=[]
for f in raw['functions']:
    status,conclusion,unknown=notes[f['va']]
    rows.append(dict(va=f['va'],sources=['functions_raw.json'],evidence=['functions_raw.json'],review_status=status,conclusion=conclusion,unknown=unknown,
                     reviewed_chunks=f['declared_chunks'] if status=='局部语义已审阅' else []))
review=dict(sources=['functions_raw.json'],counts=dict(Counter(r['review_status'] for r in rows)),functions=rows,
            scope='13项完整本函数局部语义；5项只审播种/取样局部；4项已有审阅复用')
(BASE/'function_review.json').write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
lines=['逐函数分级与边界','============================================================================',
       '22个函数全部保存原证；13项局部语义、5项部分分析、4项复用已有审阅。',
       'partial仅指下列局部，不表示整个声明块的语义已完成。','']
for r in rows:
    lines.extend([r['va']+'  '+r['review_status'],'  '+r['conclusion'],'  边界：'+r['unknown'],''])
(BASE.parent/'06_逐函数分级与边界.txt').write_text('\n'.join('// '+line if line else '//' for line in lines)+'\n',encoding='utf-8')
paths=['docs/逆向资料/专题/游戏时间与计时调度/03_局部节拍与排除项.txt',
       'docs/逆向资料/专题/股票与交易流程/04_行情历史与边界评选.txt',
       'docs/逆向资料/专题/股票与交易流程/05_逐函数覆盖与分级.txt',
       'docs/逆向资料/专题/音频系统/02_对象字段与生命周期.txt',
       'docs/逆向资料/全量分析/export_function_group.py']
(BASE/'reuse_manifest.json').write_text(json.dumps(dict(sources=[dict(path=p,sha256=hashlib.sha256((PROJECT/p).read_bytes()).hexdigest()) for p in paths]),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(review['counts'],ensure_ascii=True))
