"""严格分层主体、指定复用、桥与owner导航；不写中央。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DOCS = ROOT / 'docs/逆向资料'
raw = json.loads((HERE/'bounded_raw.json').read_bytes())
descriptions = [
    ('八间接call点/七次执行，经全局函数槽+60/+64交Type和六配置项；3参caller清栈', '回调绑定、文本格式、结果处理与声音播放未知'),
    ('文本字段复制与8E1800替换后，垂直/水平/多行/自动尺寸顺序调用，间隔最后复制', '基础复制器完整语义、失败原子性与源目标非法别名未知'),
    ('低BYTE写Multiline后以已有水平/垂直模式依次重布局', '非0/1值不规范化；返回非统一成功码'),
    ('空文本只存水平模式；AutoSize/Multiline/有符号宽度比较决定水平矩形', '溢出、非法模式、字体业务和实际渲染未验证'),
    ('空文本门、单/多行及分段链计数，三垂直模式写矩形；辅助调用实际四栈参', '宽度表长度、链无环、非法尺寸、运行字体及返回统一意义未知'),
    ('文本非空令高度等行高否则0，再更新四矩形字段；无栈参返回高度', '没有声音、分配或绘制行为；外部字段合法性未知'),
    ('各键存在才覆盖五DWORD；CoolDown通用词法有符号>0写BYTE，缺键保留', '旧版本来源仅指定371B重核；基础读与解析失败边界未完整展开'),
]
formal = json.loads((HERE/'formal_functions.json').read_bytes())
functions = []
for i,(f,(conclusion,unknown)) in enumerate(zip(formal['functions'],descriptions)):
    functions.append(dict(va=f['va'],status='完整函数静态审阅',conclusion=conclusion,unknown=unknown,
        evidence='证据/formal_functions.json#/functions/'+str(i),
        document='01_配置字段与输出ABI.txt' if i in (0,6) else '02_文本复制与布局分支.txt',
        coverage_origin=f['coverage_origin']))
functions.append(dict(va='0x90bfb0',status='完整函数静态审阅',
    conclusion='低BYTE写AutoSize；非0调用90BF60，0以this+0A4地址和+0A8值调用8E1FB0',
    unknown='8E1FB0后端完整尺寸恢复契约未展开',evidence='证据/dependency_raw.json#/functions/0',
    document='02_文本复制与布局分支.txt',coverage_origin='本批新增短依赖完整主体'))
reuse = [
    ('专题/提示文本生命周期/证据/lifecycle.json','0x8e06f0','通用大小写不敏感枚举；true/false非全部词法，未知可先交全局+4C回调'),
    ('专题/文本宽度到字符位置/证据/width_position.json','0x8e1800','替换拥有UTF-16文本与宽度表，回收分段节点；相同文本可不修改'),
    ('专题/文本宽度到字符位置/证据/width_position.json','0x924fc0','遍历16位NUL求单元数，无NULL或上限检查'),
    ('专题/文本宽度到字符位置/证据/width_position.json','0x8e0a00','全局+5128门控制词边界扫描，累计BYTE宽>=剩余空间返回AL0；只消费前三参'),
]
for path,va,conclusion in reuse:
    data=json.loads((DOCS/path).read_bytes())
    index=next(i for i,f in enumerate(data['functions']) if f['va']==va)
    functions.append(dict(va=va,status='完整函数静态审阅',conclusion=conclusion,
        unknown='仅指定本体既有契约复用，不认领所有调用者与运行约束',
        evidence='../'+path.removeprefix('专题/')+'#/functions/'+str(index),
        document='02_文本复制与布局分支.txt',coverage_origin='既有完整短契约指定范围复用；不计新增'))
for i,b in enumerate(raw['verified_direct_bridges']):
    functions.append(dict(va=b['start_va'],status='直接桥静态核验',conclusion='E9到'+b['target_va'],
        unknown='不证明业务动态可达',evidence='证据/bounded_raw.json#/verified_direct_bridges/'+str(i),
        document='03_证据分层与协作边界.txt',coverage_origin='直接桥；不计业务主体'))
dep=json.loads((HERE/'dependency_raw.json').read_bytes())
for i,b in enumerate(dep['thunks']):
    if any(f['va']==b['va'] for f in functions):continue
    functions.append(dict(va=b['va'],status='直接桥静态核验',conclusion='E9到'+b['target'],
        unknown='后端完整语义另核',evidence='证据/dependency_raw.json#/thunks/'+str(i),
        document='02_文本复制与布局分支.txt',coverage_origin='直接桥；不计业务主体'))
windows=[]
for va in ('0x90b480','0x8f7a80','0x90b0a0'):
    indices=[i for i,w in enumerate(raw['explicit_owner_windows']) if w['owner_va']==va]
    windows.append(dict(owner_va=va,window_status='仅有限窗口导航',window_conclusion='指定调用点及邻近字段访问',
        evidence=['证据/bounded_raw.json#/explicit_owner_windows/'+str(i) for i in indices],
        document='03_证据分层与协作边界.txt',unknown='完整owner与全部参数生产不在窗口',
        coverage_origin='不计函数审阅'))
output=dict(stage='作者静态审阅；独审另记',disk_sha256=raw['disk_sha256'],functions=functions,windows=windows,
            scope='六新主体加旧局部晋升、短依赖、指定复用与桥分层；owner纯导航')
(HERE.parent/'函数审阅清单.json').write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'functions':len(functions),'windows':len(windows)}))
