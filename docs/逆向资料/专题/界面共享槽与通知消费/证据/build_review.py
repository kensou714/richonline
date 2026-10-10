"""从已人工审阅的七主体与精确原证生成分级入口，不改变中央覆盖。"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
raw = json.loads((HERE / 'bounded_raw.json').read_text(encoding='utf-8'))
descriptions = [
    ('清A84FE8；控件2虚+90接原栈参，再原this虚+A4；RET4', '动态虚目标、查找返回NULL和回调撤销生命周期未知'),
    ('一个栈参原样写DWORD A84FE8并保留EAX；RET4', '注册实参来源、有效性、并发及寿命未知'),
    ('事件访问值1时虚+9C、选择71、非NULL直接call[A84FE8]；RET8与AL1', '无显式回调栈参但ECX不保证；回调后本体不清槽；只AL1非EAX1'),
    ('基类/静态表/this+5C计时初始化，清A859C4及this+58，返回this；含异常尾块', '调用者只局部窗；异常范围表内容未采；无完整生命周期保证'),
    ('三组控件事件注册与字段初始化；A859C4为0时先置1再保存内层+158/+15C到外层E8/EC', '捕获值业务类型及归还未知；门非0仅跳过捕获；无失败回滚'),
    ('控件2注册事件10，参数4操作及选择130调用后清A859CC；RET4', '四处置1路径已局部补核，完整界面语义和恢复周期未知'),
    ('事件值2处理129/130；this+48非0且A859CC为0时无显式参数调用796BE0；RET8与AL1', '只AL1非EAX1；槽非对象；不宣称退出全链或运行时触发'),
]
functions = []
for index, (f, (conclusion, unknown)) in enumerate(zip(raw['functions'], descriptions)):
    functions.append(dict(va=f['seed_va'], status='完整函数静态审阅', conclusion=conclusion,
        unknown=unknown, document='01_三组独立槽与ABI.txt',
        evidence='证据/formal_functions.json#/functions/'+str(index),
        coverage_origin='本批新增完整主体'))
for index, va, conclusion in ((10, '0x81bc80', '转调81BCB0后返回this；一个栈参RET4'),
                              (11, '0x81bcb0', '参数写this，GetTickCount写this+4；计时设置非直接通知')):
    functions.append(dict(va=va, status='完整函数静态审阅', conclusion=conclusion,
        unknown='调用实例具体计时业务及运行时行为不由短契约保证',
        document='02_入边复用与可达边界.txt',
        evidence='../主界面角色通知/证据/notify_contract.json#/functions/'+str(index),
        coverage_origin='既有完整短契约指定字节复用；不计新增'))
functions.append(dict(va='0x796be0', status='完整函数静态审阅',
    conclusion='当前12字节5指令写BYTE[A76691]=1后RET，无显式参数和ECX消费',
    unknown='不据此认领完整退出、运行触发或恢复周期',
    document='02_入边复用与可达边界.txt',
    evidence='证据/dependency_raw.json#/functions/0',
    coverage_origin='既有短函数当前完整补证；中央去重不计新增'))
for relative, index, va, conclusion in (
    ('727F控件状态接口/证据/seeds.json', 1, '0x728060', '无栈参返回DWORD[this+15C]'),
    ('727F控件状态接口/证据/seeds.json', 2, '0x728120', '无栈参返回DWORD[this+158]'),
    ('40B0系列事件/证据/ui24_control_id.json', 0, '0x7278e0', '无栈参返回DWORD[this+4]'),
):
    functions.append(dict(va=va, status='完整函数静态审阅', conclusion=conclusion,
        unknown='字段业务类型及实例寿命不由短访问器保证；无NULL检查',
        document='02_入边复用与可达边界.txt', evidence='../'+relative+'#/functions/'+str(index),
        coverage_origin='既有完整短契约指定字节复用；不计新增'))
for index, b in enumerate(raw['verified_direct_bridges']):
    functions.append(dict(va=b['start_va'], status='直接桥静态核验',
        conclusion='5字节E9到'+b['target_va'], unknown='不证明运行绑定和业务可达',
        document='02_入边复用与可达边界.txt',
        evidence='证据/bounded_raw.json#/verified_direct_bridges/'+str(index),
        coverage_origin='直接桥；不计业务主体'))
windows = [dict(owner_va='0x6e8d10', window_status='仅调用路径窗口导航',
    window_conclusion='6E8D4D..6E8D77的非NULL对象经6E8D60调用7348F0，保存返回值',
    unknown='前置EAX生产、完整owner与生命周期未恢复',
    document='02_入边复用与可达边界.txt',
    evidence='证据/bounded_raw.json#/explicit_owner_windows/0',
    coverage_origin='有限owner窗；不计函数审阅')]
for va, indices, conclusion in (
    ('0x733960', [0, 1, 2, 3], 'var14/var24为0分支在733B1B/733D76写A859CC=1'),
    ('0x734000', [4, 5], 'var8为0分支在7340E6写A859CC=1，局部末AL0跳7342FB'),
    ('0x751180', [6, 7], 'var9C为0分支在75137C写A859CC=1'),
):
    windows.append(dict(owner_va=va, window_status='仅调用路径窗口导航', window_conclusion=conclusion,
        unknown='局部变量生产者、所有前驱、动态用户触发和完整owner未知',
        document='02_入边复用与可达边界.txt',
        evidence=['证据/slot_owner_context.json#/windows/'+str(index) for index in indices],
        coverage_origin='有限owner窗；不计函数审阅'))
output = dict(stage='作者七主体静态审阅完成；独立审阅另记', disk_sha256=raw['disk_sha256'],
              scope='七主体、指定复用、直接桥及唯一owner局部窗分层；三槽非同生命周期',
              functions=functions, windows=windows)
(HERE.parent / '函数审阅清单.json').write_text(
    json.dumps(output, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(json.dumps({'functions': len(functions), 'windows': len(windows), 'new_complete_subjects': 7}))
