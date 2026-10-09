"""整理已人工核对的局部函数结论；不按扫描模板把候选提升为语义审阅。"""
from pathlib import Path
from collections import Counter
import hashlib
import json

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent
scan = json.loads((BASE / 'rtti_scan.json').read_text('utf-8'))
nav = json.loads((BASE / 'ida_navigation.json').read_text('utf-8'))
raw = json.loads((BASE / 'functions_raw.json').read_text('utf-8'))

# 下列条目来自逐条汇编和尾块核对；函数外依赖继续引用已有专题。
notes = {
    '0x62b540': 'length_error构造：先62B590构造logic_error基类，再将入口ECX所指对象+0写A318C0，返回原对象。',
    '0x62b590': 'logic_error构造：920C70初始化exception基类，+0写A318D0；以this+12为目标复制参数短字符串。尾块A117B0清理exception基类。',
    '0x62b620': 'logic_error的what包装：保存入口ECX，以this+12调用62B8E0取得字符串数据指针；伪码遗漏ECX偏移。',
    '0x62b650': 'logic_error标量删除析构：先62B6A0；栈flag低位1才调用91FC60释放原this；返回原指针，retn4。',
    '0x62b6a0': 'logic_error析构：+0回写A318D0，62B8A0清理this+12字符串，然后920E50清理exception基类；尾块同样调用基类清理。',
    '0x62b720': 'length_error析构：+0回写A318C0，随后调用62B6A0清理logic_error基类。',
    '0x62b760': 'length_error标量删除析构：先62B720；flag低位1时释放原this，返回原this。',
    '0x62c760': 'length_error拷贝构造：先62C7B0复制logic_error基类，再+0写A318C0。',
    '0x62c7b0': 'logic_error拷贝构造：先920D70复制exception；+0写A318D0，62B7B0复制源+12到目标+12；尾块清理exception。',
    '0x62d4c0': 'out_of_range构造：先62B590构造logic_error，再+0写A318FC；this来源为入口ECX保存的局部槽。',
    '0x62d510': 'out_of_range析构：+0回写A318FC，再62B6A0清理logic_error；回写本身不是升级或事件分派。',
    '0x62d550': 'out_of_range标量删除析构：先62D510，再按flag低位1释放原this；返回原this。',
    '0x62dc70': 'out_of_range拷贝构造：先62C7B0复制logic_error，再+0写A318FC。',
    '0x7db7b0': 'locale::facet构造：+0写A319D0，+4写栈参数；其引用计数意义须结合使用者确认。',
    '0x7db7f0': 'locale::facet标量删除析构：先7DB840回写表，flag低位1才释放原this。',
    '0x7db840': 'locale::facet析构：只将入口ECX对象+0回写A319D0，没有在本函数释放+4或对象内存。',
    '0x835e20': 'ios_base构造局部：+0写A31990；其余对象字段没有在本函数初始化，不能从此包装恢复完整ios布局。',
    '0x835e70': 'ios_base标量删除析构：先91C6D0；flag低位1才释放原this，RTC栈检查不属于业务行为。',
    '0x914770': 'vector长度异常抛出：构造临时短字符串vector<T> too long，62B590构造栈异常对象，首DWORD写A318C0后以length_error ThrowInfo调用_CxxThrowException。尾块仅清理临时字符串。',
    '0x914800': '另一vector长度异常抛出包装；和914770流程一致，独立地址与尾块保留，不能折叠成一次字节审阅。',
    '0x91c010': 'ios_base::failure构造：先91C040构造runtime_error基类，再+0写A31964。',
    '0x91c040': 'runtime_error构造：920C70初始化exception，再+0写A31974、复制参数字符串到this+12；尾块清理exception。',
    '0x91c0c0': 'runtime_error的what包装：以this+12调用62B8E0取字符串数据；没有在本函数分配或复制文本。',
    '0x91c0e0': 'runtime_error标量删除析构：先91C120；flag低位1才释放原this。自动CSessionMapPtrToPtr类名与RTTI不一致。',
    '0x91c120': 'runtime_error析构：+0写A31974，清理this+12字符串，再920E50清理exception；尾块也清理exception。自动CSessionMapPtrToPtr名字不作类证据。',
    '0x91c190': 'ios_base::failure析构：+0写A31964，再91C120清理runtime_error基类。',
    '0x91c1c0': 'ios_base::failure标量删除析构：先91C190，再按flag低位1释放原this。',
    '0x91c200': 'ios_base::failure拷贝构造：先91C230复制runtime_error基类，再+0写A31964。',
    '0x91c230': 'runtime_error拷贝构造：先920D70复制exception，+0写A31974，复制源+12字符串到目标+12；尾块清理exception。',
    '0x91c6d0': 'ios_base析构局部：+0写A31990；+4为0或全局字节计数减一后有符号<=0才调用91CB60清理并释放+36对象。具体_Tidy及分配器依赖未闭合。',
    '0x91d750': 'locale::_Locimp构造：7DB7B0(1)初始化facet；+0写A319C4，+8/+12/+16清零，+20写bool，+24构造星号字符串；尾块清理facet。',
    '0x91d800': 'locale::_Locimp标量删除析构：先91D840，再按flag低位1释放原this。',
    '0x91d840': 'locale::_Locimp析构局部：回写A319C4，持Lockit(0)反向遍历+8表、数量+12；非空项7DA7C0后交7DB2C0处理，释放表，再解锁、清理+24字符串及facet。三个尾块分别清理facet、字符串和锁。',
    '0x91f3c0': 'bad_alloc文本构造：将栈char*参数地址传920CF0，随后+0写A31A84。',
    '0x91f3f0': 'bad_alloc析构：+0写A31A84，再920E50清理exception。',
    '0x91f420': 'bad_alloc标量删除析构：先91F3F0，再按flag低位1释放原this。',
    '0x91f460': 'bad_alloc拷贝构造：920D70后+0写A31A84；自动名为bad_typeid，但实际虚表及COL类型为bad_alloc。',
    '0x920c70': 'exception默认构造行为：+0写A31B64，+4文本指针与+8所有权标志清零，返回原this；自动Concurrency析构名错误。',
    '0x920cb0': 'exception标量删除析构：先920E50；flag低位1才91FC60释放原this。',
    '0x920cf0': 'exception文本构造：读取参数char**所指文本，malloc(strlen+1)保存+4，成功才strcpy；+8设1，即使malloc返回0仍保留1。',
    '0x920d70': 'exception拷贝构造：复制源+8；非0时复制源+4文本到新malloc内存，0时直接借用源+4指针；+0写A31B64。',
    '0x920e50': 'exception析构：+0回写A31B64，仅+8非0时free(+4)；本函数没有释放this，也没有清零文本字段。',
    '0x920e90': 'exception::what：+4非0时返回文本指针，否则返回Unknown exception字面量；所有权不影响选择。',
    '0x920ec0': 'bad_cast文本构造：先920CF0复制文本，再+0写A31B8C。',
    '0x920ef0': 'bad_cast标量删除析构：先920F60，再按flag低位1释放原this。',
    '0x920f30': 'bad_cast拷贝构造：先920D70，再+0写A31B8C；自动bad_typeid名与真实COL名不符。',
    '0x920f60': 'bad_cast析构：+0写A31B8C，随后920E50清理exception。',
    '0x920f90': 'bad_typeid文本构造：先920CF0，再+0写A31B9C。',
    '0x920fc0': 'bad_typeid标量删除析构：先921030，再按flag低位1释放原this。',
    '0x921000': 'bad_typeid拷贝构造：先920D70，再+0写A31B9C。',
    '0x921030': 'bad_typeid析构：+0写A31B9C，随后920E50清理exception。',
    '0x921090': '__non_rtti_object标量删除析构：先921100，再按flag低位1释放原this。',
    '0x921100': '__non_rtti_object析构：+0写A31BAC，随后921030清理bad_typeid，符合CHD继承链。',
    '0x921130': 'type_info析构：+0写A31BBC，lock(14)后+4非0则free_base；正常及SEH finally均unlock(14)。+4与静态TD的spare槽重合，运行态可变化。',
    '0x9211e0': 'type_info标量删除析构：先921130，再按flag低位1释放原this。',
    '0x921300': 'type_info名义拷贝包装：只写+0=A31BBC并返回原this；本函数未读取源参数或复制名称，不能当普通完整拷贝实现。',
}
reused = {'0x7aa110', '0x63e6a0', '0x62f160', '0x62f620'}
rows = []
for f in raw['functions']:
    a = f['va']
    if a in notes:
        status, conclusion = '局部语义已审阅', notes[a]
        unknown = '只闭合本函数控制流、this来源和直接字段操作；外部依赖、动态运行及完整类布局未全部闭合。'
    elif a in reused:
        status = '复用已有审阅'
        conclusion = '动画0工厂/构造/虚函数链已在角色与精灵动画专题记录；本专题只补虚表前槽不含COL的证据。'
        unknown = '不计作本专题新增语义审阅；其它动画类和槽位仍依原专题边界。'
    else:
        status = '仅导航'
        conclusion = '因写入length_error或out_of_range栈异常对象进入候选；完整STL容器业务控制流未在本专题逐条审阅。'
        unknown = '异常写入所属函数并不等于已恢复全部容器操作、模板类型及异常处理语义。'
    rows.append(dict(va=a, sources=['functions_raw.json'], review_status=status,
                     conclusion=conclusion, unknown=unknown,
                     reviewed_chunks=f['declared_chunks'] if a in notes else []))
assert set(notes) <= {f['va'] for f in raw['functions']}
review = dict(sources=['functions_raw.json'], counts=dict(Counter(r['review_status'] for r in rows)), functions=rows,
              scope='人工读取56项局部控制流；4项复用、8项仅导航，均不等于完整类型业务恢复')
(BASE / 'function_review.json').write_text(json.dumps(review, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def textfile(name, lines):
    (ROOT / name).write_text('\n'.join('// ' + line if line else '//' for line in lines) + '\n', encoding='utf-8')

type_names = {r['va']:r['decorated_name'] for r in scan['type_descriptors']}
hierarchies = {h['va']:h for h in scan['hierarchies']}
locators = {c['va']:c for c in scan['locators']}
lines = ['确认类型与继承导航', '============================================================================',
         '本表取自完整COL链；装饰名直接记录磁盘值，不依赖IDA自动类名。',
         '连续代码指针数仅为导航前缀。所有14 COL的offset/cdOffset均0；不推断全EXE不存在多重/虚继承。', '']
for v in scan['vftables']:
    c = locators[v['locator']]
    h = hierarchies[c['hierarchy']]
    t = type_names[v['type_descriptor']]
    lines.extend([t, '  TD=' + v['type_descriptor'] + '  COL=' + c['va'] + '  CHD=' + h['va'],
                  '  vftable=' + v['va'] + '  连续入口数=' + str(len(v['entries'])),
                  '  BCD次序=' + ' -> '.join(type_names[b['type_descriptor']] + '(mdisp=' + str(b['pmd']['mdisp']) + ')' for b in h['bases'])])
    n = next(n for n in nav['vtable_references'] if n['vtable'] == v['va'])
    lines.append('  槽入口=' + ', '.join(r['entry'] + '=>' + r['implementation'] for r in n['targets']))
    lines.append('')
lines.extend(['仅有类型描述器、未连接完整COL链的6项',
              '  CAtlException@ATL；BufferOverflowException；PosOutOfRangeException；',
              '  BufferUnderflowException；InvalidMarkException；?$_Iosb@H@std。',
              '  TD可被EH CatchableType引用；TD存在不能推出对象有虚表。',
              '  ios_base的CHD包含_Iosb<int>，该基类PMD.mdisp=4；这是已确认的非零基类偏移。',
              '  其余本批BCD均(mdisp=0,pdisp=-1,vdisp=0)、attrs=0；不能用此结果推断未知游戏类。'])
textfile('02_确认类型与继承导航.txt', lines)
lines = ['逐函数局部审阅清单', '============================================================================',
         '来源：证据/functions_raw.json；状态：证据/function_review.json。',
         '56项局部语义已审阅；4项复用已有动画审阅；8项仅导航。',
         '逐项局部审阅覆盖对应声明块与异常尾块；没有把导出函数数当新增完整审阅数。', '']
for r in rows:
    lines.extend([r['va'] + '  ' + r['review_status'], '  ' + r['conclusion'], '  边界：' + r['unknown'], ''])
textfile('06_逐函数局部审阅清单.txt', lines)
print(json.dumps(review['counts'], ensure_ascii=True))

project = BASE.parents[4]
reuse_paths = [
    'docs/逆向资料/专题/角色与精灵动画/证据/47类动画虚表导航.json',
    'docs/逆向资料/专题/短字符串与缓冲所有权/01_对象布局与操作契约.txt',
    'docs/逆向资料/专题/短字符串与缓冲所有权/02_扩容异常与误名核验.txt',
    'docs/逆向资料/全量分析/export_function_group.py',
]
manifest = dict(scope='只记录复用时原始证据的路径与摘要；不把其它专题重复计为新增审阅',
                sources=[dict(path=p, sha256=hashlib.sha256((project/p).read_bytes()).hexdigest()) for p in reuse_paths])
(BASE/'reuse_manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
