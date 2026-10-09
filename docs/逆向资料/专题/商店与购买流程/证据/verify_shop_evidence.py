"""离线验证本专题全部原证；逐项分级，不以导出数量冒充语义完成数量。"""
from pathlib import Path
import collections
import hashlib
import json
import struct

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]
blob = (ROOT / 'RnClient.exe').read_bytes()
pe = struct.unpack_from('<I', blob, 0x3c)[0]
image_base = struct.unpack_from('<I', blob, pe + 52)[0]
section_count = struct.unpack_from('<H', blob, pe + 6)[0]
optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
sections = [struct.unpack_from('<IIII', blob, pe + 24 + optional_size + 40*i + 8)
            for i in range(section_count)]

def readva(ea, size):
    for virtual_size, rva, raw_size, raw_offset in sections:
        delta = ea-image_base-rva
        if 0 <= delta and delta+size <= raw_size:
            return blob[raw_offset+delta:raw_offset+delta+size]
    return None

def verify(row):
    ea = int(row['va'], 16)
    disk = readva(ea, row['size'])
    if row.get('disk_hex') is None:
        assert disk is None, row['va']
        return False
    assert disk is not None and disk.hex() == row['disk_hex'] == row['idb_hex'], row['va']
    assert row['matching'] is True, row['va']
    return True

# 已分析仅指所列函数自己的全部可见分支，不递归保证全部依赖实现。
complete = {
 '63e100':'按当前行动槽取角色指针', '63e210':'返回地图子对象G+0x65C',
 '63e440':'读取this+4 DWORD；请求取低WORD', '63e560':'参数槽与G+8本地槽比较',
 '63e590':'返回G+0xC44请求身份子对象', '63f5f0':'读取角色点券DWORD+0x5E8',
 '63f760':'当前行动槽与本地槽比较', '64f200':'返回状态对象+100指针，不是直接取地图mode',
 '64f710':'核验GmsvID，不等则弹窗并返回假',
 '6609b0':'4030复制商品表、初开窗口/付费刷新分支和等待',
 '660b00':'4031购买和退出全部分支；无槽范围或pending检查',
 '660cb0':'4032出售整槽并返一次算术半价点券',
 '660e30':'4033无返款移除库存与本地操作恢复',
 '6939e0':'清pending与duration，保留其他等待字段', '693be0':'构造6080和默认+3=-1',
 '694080':'初始化UI刷新mask与force', '6940b0':'1128字节道具属性条目+60价格',
 '6940e0':'商店槽signed WORD物品ID', '694110':'商店槽signed WORD数量',
 '6e2590':'根控件隐藏与窗口状态2；无直接网络提交',
 '6e4440':'UI槽存在时转交窗口+68启用入口',
 '6e4520':'窗口存在并且+80返回真时判显示',
 '6e7840':'UI20分配724字节并调用构造',
 '6fa100':'窗口+68将低BYTE启用值转交根控件+196',
 '6fb340':'UI20基础构造与虚表设置', '7125b0':'转发UI12启用值',
 '715410':'十二商品及按钮回调注册，金豆提示初始化',
 '7155d0':'重置刷新次数与提示状态',
 '715620':'按mask/force更新商品、点券与刷新按钮全部条件',
 '715a30':'主状态2的Esc取消与Shift+Space刷新通知',
 '715b10':'置商品提示允许标志W+589',
 '715c80':'商品点击、退出、刷新全部控件分支与请求',
 '715fb0':'商品/刷新按钮悬浮提示构造', '7160c0':'离开控件清对应提示标志',
 '727850':'比较本地金豆字段与请求金额', '727b10':'读取配置对象+544 BYTE',
 '7280f0':'构造0032弃卡请求', '7281f0':'构造0031出售请求',
 '728320':'返回this，供商品表首地址使用', '728340':'返回G+0xC84商品表',
 '728360':'构造0035刷新请求',
 '7bb430':'写pending类型、duration和起始tick，末参不读',
 '7bc050':'0030请求6字节与严格整数-1关闭窗口', '7d6020':'构造0030请求',
 '7d6f90':'G+83809 signed BYTE>0停业谓词',
 '7efcb0':'4030注册桥接：栈参数G转ECX，原记录入栈',
 '7efcd0':'4031注册桥接：栈参数G转ECX，原记录入栈',
 '7efcf0':'4032注册桥接：栈参数G转ECX，原记录入栈',
 '7efd10':'4033注册桥接：栈参数G转ECX，原记录入栈',
 '7f86a0':'按group0/1/2读取槽ID，非法组返回-1；槽不查范围',
 '7f8710':'按group0/1/2读取槽数量，非法组返回-1；槽不查范围',
 '7f8920':'group0 WORD数量扣减、signed清空与本地栏刷新',
 '7f8e70':'8个group0槽均非空返回1，存在空槽返回0',
 '7f9d20':'点券DWORD相加与可选通知',
 '7f9d70':'点券DWORD相减、结果signed<0归零与可选通知',
 '7fd7a0':'读取角色+1416 BYTE', '7fdc30':'返回配方提示字符串this+16',
 '810170':'复制72字节商品表', '8101a0':'清商店槽ID/数量，保留余字节',
}
partial = {
 '63e5b0':'按G+0x640取队列头；底层游标实作沿用既有队列专题',
 '650110':'刷新扣本地金豆及本地通知链；通知41消费者和远端同步未展开',
 '6e2770':'调用音效21接口；音频内部由音频专题负责',
 '6e3b40':'本篇仅使用显示UI20和持续值的接口；通用窗口生命周期未重审',
 '6e4020':'关闭入口直接链与+64；关联窗口及容器依赖未全部展开',
 '6e4640':'转交窗口+16刷新；前后公共保护实作未展开',
 '6e47f0':'逐窗口更新与超时入关闭列表；动态弹出辅助效果未展开',
 '710d60':'仅Shift+F的0032路径与UI20门的所在分支；普通快捷键见输入专题',
 '711c80':'仅商店上下文0031提交；普通卡片使用和UI22确认范围外',
 '712610':'操作开关与UI0掩码64，鼠标内部辅助未展开',
 '716120':'两类提示的绘制条件与40字符估行；字体/图像内部未展开',
 '7bb530':'仅pending19自动取消和共同门控；其余pending见等待专题',
 '7c54b0':'仅type10商店停业提示/返回0；其余分支见落点专题',
 '7f8780':'购入空槽插入、后续合成与返回值；配方许可规则仍局部',
 '800fd0':'配方扫描/按同ID槽计数/替换主干；配方合法域与结果许可依赖待查',
}
todo = {'660f10':'相邻4034传送回复，仅排除与商店刷新混同，未做本篇语义审阅'}

functions = {}
thunks = {}
files = []
for path in sorted(BASE.glob('shop_*.json')):
    data = json.loads(path.read_text(encoding='utf-8'))
    files.append({'path': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    if isinstance(data, list):
        for row in data:
            verify(row)
        continue
    assert data['disk_sha256'] == hashlib.sha256(blob).hexdigest()
    for f in data['functions']:
        for row in f['byte_ranges']:
            verify(row)
        assert f['bytes_match_disk']
        if f['va'] in functions:
            assert functions[f['va']]['byte_ranges'] == f['byte_ranges']
        f['evidence_file'] = path.name
        functions[f['va']] = f
    for t in data['thunks']:
        verify(t)
        thunks[t['va']] = t

review = []
for va, f in sorted(functions.items(), key=lambda item: int(item[0], 16)):
    key = va[2:]
    options = [(level, rows[key]) for level, rows in [('已分析', complete), ('局部分析', partial), ('待深入', todo)] if key in rows]
    assert len(options) == 1, va
    level, scope = options[0]
    review.append({'va': va, 'status': level, 'scope': scope, 'conclusion': scope,
                   'evidence': '证据/'+f['evidence_file'],
                   'byte_ranges': len(f['byte_ranges']), 'bytes_match_disk': True})
assert len(complete)+len(partial)+len(todo) == len(review)
counts = dict(collections.Counter(row['status'] for row in review))
manifest = {'scope': '本专题函数自己的审阅深度；共享函数重复出现不计项目新增覆盖；依赖不自动完成',
            'status_definitions': {'已分析': '本体分支与作用已阅读并有对应正文；外部实现不递归承诺',
                                  '局部分析': '仅清单指定路径或主干已确认', '待深入': '保留原证，无业务完成声明'},
            'counts': counts, 'functions': review}
(BASE.parent / '函数审阅清单.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
summary = {'disk_sha256': hashlib.sha256(blob).hexdigest(),
           'ida_input_sha256': 'cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77',
           'unique_functions': len(functions), 'semantic_counts': counts,
           'instruction_ranges': sum(len(f['byte_ranges']) for f in functions.values()),
           'instruction_bytes': sum(r['size'] for f in functions.values() for r in f['byte_ranges']),
           'unique_direct_thunks': len(thunks), 'function_mismatches': [], 'thunk_mismatches': [],
           'additional_data': 'UI20虚表172字节及17个虚表入口跳板通过；A87490无PE原始区间，不计通过',
           'evidence_snapshots': files,
           'boundary': '离线核验已导出的IDA原证；不验证未导出的依赖、运行时数据、服务端或实机交互'}
(BASE / '核验汇总.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(json.dumps({'unique_functions': len(functions), 'counts': counts, 'instruction_bytes': summary['instruction_bytes'], 'thunks': len(thunks)}, ensure_ascii=False))
