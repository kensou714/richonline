"""只读核对输入专题证据与当前 PE；生成逐函数审阅清单和快捷键导航。"""
import hashlib
import json
import re
import struct
from pathlib import Path

folder = Path(__file__).resolve().parent
root = folder.parents[3]
data = json.loads((folder / 'ida_input_raw.json').read_text(encoding='utf8'))
binary = (root / 'RnClient.exe').read_bytes()
pe = struct.unpack_from('<I', binary, 0x3c)[0]
count = struct.unpack_from('<H', binary, pe + 6)[0]
optional_size = struct.unpack_from('<H', binary, pe + 20)[0]
base = struct.unpack_from('<I', binary, pe + 52)[0]
sections = []
for index in range(count):
    pos = pe + 24 + optional_size + 40 * index
    _, rva, size, pointer = struct.unpack_from('<IIII', binary, pos + 8)
    sections.append((rva, size, pointer))


def read_va(va, size):
    relative = va - base
    for start, length, offset in sections:
        if start <= relative and relative + size <= start + length:
            return binary[offset + relative - start:offset + relative - start + size]
    return None


checks = []
for function in data['functions'].values():
    ranges = []
    for chunk in function['ranges']:
        original = bytes.fromhex(chunk['idb_bytes_hex'])
        current = read_va(int(chunk['start'], 16), len(original))
        ranges.append({'start': chunk['start'], 'end': chunk['end'],
                       'size': len(original), 'match': original == current,
                       'idb_sha256': hashlib.sha256(original).hexdigest(),
                       'disk_sha256': hashlib.sha256(current).hexdigest() if current else None})
    checks.append({'ea': function['ea'], 'ranges': ranges,
                   'match': all(item['match'] for item in ranges)})
regions = []
for region in data['data_regions']:
    original = bytes.fromhex(region['bytes_hex'])
    current = read_va(int(region['start'], 16), len(original))
    regions.append({'start': region['start'], 'kind': region['kind'],
                    'size': len(original), 'match': original == current})
verification = {'idb_input_sha256': data['idb_input_sha256'],
                'disk_sha256': hashlib.sha256(binary).hexdigest().upper(),
                'functions': checks, 'data_regions': regions,
                'matched_functions': sum(item['match'] for item in checks),
                'matched_data_regions': sum(item['match'] for item in regions)}
(folder / 'input_verification.json').write_text(
    json.dumps(verification, ensure_ascii=False, indent=2) + '\n', encoding='utf8')

# 逐函数状态严格区分局部语义审阅、跳板核对及仅导出候选。
reviewed = {int(address, 16) for address in '''
626050 6999e0 699c70 647890 6501e0 705c70 70ab40 70b5c0 70b9c0
70c4b0 70d990 70ed20 710d60 7128e0 713d20 715a30 716c40 71f030
736820 7a3190 7a3700 7a29e0 81dca0 81dec0 81dc20 624ca0
64ed30 64ed60 691c60 691e30 629f80 7280c0 691bd0 7a47b0
6278f0 62a0f0 8e8800 8e8a10 8e0ed0 8ea570 8e9ab0 8e93a0
8e97e0 8e7e40 8ea080 728260 6939e0 7bb870 7bbb80 7bc480 7bba10
8ea000 8ea020 8ea040 8ea060 8e9570 8e95f0 8e96e0 8e9640
8e9730 8e9760 8e97a0 8e9a40 8e9b40 8e9b90 8e9be0
627270 81db50
'''.split()}
review = []
conclusions = json.loads((folder / 'input_review_conclusions.json').read_text(encoding='utf8'))
thunk_targets = json.loads((folder / 'input_thunk_targets.json').read_text(encoding='utf8'))
window_labels = {}
for mapping in data['window_keymap']:
    window_labels.setdefault(mapping['target'], []).append(
        f"UI{mapping['slot']}/{mapping['resource'] or '未配置Intf资源'}")
edge_labels = {'606D55': '释放', '60CD40': '按下', '5FF3CF': '保持'}
neighbor_reasons = {
    '0x691c30': ('输入getter邻近函数；原伪代码比较this的第41895个WORD是否为1', '该WORD是否属于游戏事件状态及调用位置未审阅'),
    '0x691c90': ('输入getter邻近函数；原伪代码写首WORD为19', '记录类型19的调用场景、布局及发送者未审阅'),
    '0x691d00': ('输入getter邻近函数；原伪代码对this+52指向的8字节元素首字节比较2', '表结构、索引范围及类型2业务未审阅'),
    '0x691d40': ('输入getter邻近函数；原伪代码对this+52指向的8字节元素首字节比较3', '表结构、索引范围及类型3业务未审阅'),
    '0x691d80': ('输入getter邻近函数；原伪代码比较8字节元素首字节28、61、58', '三种枚举业务含义和元素访问前置条件未审阅'),
    '0x64eca0': ('释放/保持getter邻近函数；原伪代码清this首字节和+272字节', '该this对象类型及清理动作调用者未审阅'),
    '0x64ecd0': ('释放/保持getter邻近函数；原伪代码写首WORD为88', '记录类型88的完整布局与用途未审阅'),
    '0x64ed00': ('释放/保持getter邻近函数；原伪代码写首WORD为89', '记录类型89的完整布局与用途未审阅'),
    '0x7045a0': ('窗口构造定位时覆盖到的函数；原证末段设置timeGetTime及清0x80字节', '完整初始化字段及窗口业务未人工语义审阅'),
    '0x6ffb00': ('窗口构造定位时覆盖到的函数；原证包含条件operator delete', '析构对象身份、委托目标及完整生命周期未语义审阅'),
}
for key, function in data['functions'].items():
    ea = int(key, 16)
    if ea in reviewed:
        status = '静态局部语义已审阅'
        boundary = '仅按01至03篇所列路径；完整函数业务、间接调用及实机结果未全部确认'
        detail = conclusions[key]
        conclusion = detail['conclusion']
        unknown = detail['unknown']
        document = detail['document']
    elif 'attributes: thunk' in '\n'.join(function['pseudocode']):
        status = '跳板目标已核对'
        boundary = '仅跳转身份，不独立计作业务实现完成'
        target = thunk_targets[key]
        conclusion = f"{key}在{target['instruction_ea']}直接跳转至{target['target']}（{target['name']}）；已核对目标，不增加业务实现计数。"
        unknown = f"目标{target['target']}的完整业务、调用约定及间接副作用应查目标函数记录，跳板本身不提供这些结论。"
        document = 'ida_input_raw.json/functions/' + key
    else:
        status = '仅导出或按键候选定位'
        boundary = '待人工逐分支分析；不得按完整逆向完成统计'
        candidate = data['key_candidates'].get(key)
        identity = '、'.join(window_labels.get(key, []))
        if candidate:
            keys = list(dict.fromkeys(edge_labels[getter] + 'VK' + vk
                                     for getter, vk in candidate['keys']))
            immediate = list(dict.fromkeys(re.findall(r'GetAsyncKeyState\(vKey: (\d+)\)',
                                                       '\n'.join(function['pseudocode']))))
            clues = ('；'.join(keys) if keys else '未直接匹配三表getter参数')
            if immediate:
                clues += '；即时GetAsyncKeyState VK=' + ','.join(immediate)
            conclusion = f"仅定位候选{('：' + identity) if identity else ''}；搜索命中{clues}。已保存完整原证，未人工逐分支语义审阅。"
            unknown = f"{identity or key}中这些输入条件的组合次序、控件通知目标、完整门控及发送副作用尚未审阅。"
            document = '04_窗口快捷键导航.txt' if identity else 'ida_input_raw.json/key_candidates/' + key
        else:
            reason, remaining = neighbor_reasons[key]
            conclusion = '仅定位候选：' + reason + '；未人工逐分支语义审阅。'
            unknown = remaining + '。'
            document = 'ida_input_raw.json/functions/' + key
    review.append({'ea': key, 'name': function['name'], 'status': status,
                   'conclusion': conclusion, 'unknown': unknown, 'document': document,
                   'boundary': boundary, 'evidence': 'ida_input_raw.json/functions/' + key})
(folder / '函数审阅清单.json').write_text(
    json.dumps(review, ensure_ascii=False, indent=2) + '\n', encoding='utf8')

names = {8:'Backspace', 9:'Tab', 13:'Enter', 16:'Shift', 17:'Ctrl',
         18:'Alt', 27:'Esc', 32:'Space', 38:'Up', 40:'Down'}
names.update({112 + i:'F' + str(i + 1) for i in range(12)})
names.update({96 + i:'Num' + str(i) for i in range(10)})
edges = {'606D55':'释放', '60CD40':'按下', '5FF3CF':'保持'}
lines = ['// 窗口快捷键导航 / 第三批', '//',
         '// 资源身份来自已核验的第二批工厂+Intf映射；槽映射字节本批再次核验。',
         '// 每项只列直接出现的getter及VK；组合条件、分支先后仍须读取正文。',
         '// 多数入口尚仅候选定位，不代表窗口业务完整审阅。', '//']
for item in data['window_keymap']:
    candidate = data['key_candidates'][item['target']]
    keys = list(dict.fromkeys(edges[getter] + ':' + names.get(int(vk), vk)
                             for getter, vk in candidate['keys']))
    lines.extend([f"// UI{item['slot']:03}  {item['resource'] or '无Intf资源'}",
                  f"//   vtbl {item['vtable']} +{item['offset']} -> {item['thunk']} -> {item['target']}",
                  '//   ' + (' / '.join(keys) if keys else '未直接出现三张VK表getter'),
                  '//'])
(folder / '04_窗口快捷键导航.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
summary = {'functions': len(checks), 'matched': verification['matched_functions'],
           'regions': len(regions), 'matched_regions': verification['matched_data_regions'],
           'review_status': {status: sum(item['status'] == status for item in review)
                             for status in sorted({item['status'] for item in review})}}
print(json.dumps(summary, ensure_ascii=False))
if any(not item['match'] for item in checks + regions):
    raise SystemExit('证据与当前二进制不一致，请检查核验报告。')
