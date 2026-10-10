"""Rank 静态原证独立 PE / Capstone 核验；不接触 IDA 或修改客户端。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
source = (ROOT / 'RnClient.exe').read_bytes()
digest = hashlib.sha256(source).hexdigest()
assert digest == 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
pe = struct.unpack_from('<I', source, 0x3C)[0]
assert source[:2] == b'MZ' and source[pe:pe + 4] == b'PE\0\0'
assert struct.unpack_from('<H', source, pe + 24)[0] == 0x10B
base = struct.unpack_from('<I', source, pe + 52)[0]
section_at = pe + 24 + struct.unpack_from('<H', source, pe + 20)[0]
sections = [struct.unpack_from('<4I', source, section_at + n * 40 + 8)
            for n in range(struct.unpack_from('<H', source, pe + 6)[0])]
decoder = Cs(CS_ARCH_X86, CS_MODE_32)
decoder.detail = True
comparisons, instructions, bridge_rows, call_rows, navigation_only, navigation_mismatches = [], {}, [], [], [], []


def disk(va, size):
    matches = [(rva, raw_at) for _, rva, raw_size, raw_at in sections
               if base + rva <= va and va + size <= base + rva + raw_size]
    if not matches:
        return None
    assert len(matches) == 1
    rva, raw_at = matches[0]
    data = source[raw_at + va - base - rva:raw_at + va - base - rva + size]
    assert len(data) == size
    return data


def visit(value, origin):
    if isinstance(value, dict):
        if {'va', 'size', 'idb_hex', 'disk_hex'} <= value.keys():
            va, size = int(value['va'], 16), value['size']
            data = disk(va, size)
            if value['disk_hex'] is None:
                assert data is None and value['matching'] is False
                assert origin.startswith('rank_navigation_raw.json/data_refs/') or origin.startswith('rank_navigation_raw.json/global_slots/')
                navigation_only.append({'va': value['va'], 'size': size, 'origin': origin})
            else:
                assert data is not None
                assert data.hex() == value['disk_hex']
                equal = data.hex() == value['idb_hex']
                assert value['matching'] is equal
                if equal:
                    comparisons.append((va, size, origin))
                else:
                    assert origin.startswith('rank_navigation_raw.json/data_refs/') or origin.startswith('rank_navigation_raw.json/global_slots/')
                    navigation_mismatches.append({'va': value['va'], 'size': size, 'origin': origin,
                                                  'idb_hex': value['idb_hex'], 'disk_hex': data.hex()})
        for key, child in value.items():
            visit(child, origin + '/' + key)
    elif isinstance(value, list):
        for n, child in enumerate(value):
            visit(child, origin + '/' + str(n))


def instruction(row):
    va = int(row['va'], 16)
    data = disk(va, 15)
    assert data is not None
    decoded = list(decoder.disasm(data, va, count=1))
    assert len(decoded) == 1
    insn = decoded[0]
    if 'size' in row:
        assert insn.size == row['size']
    if 'idb_hex' in row:
        assert insn.bytes.hex() == row['idb_hex']
    record = {'va': hex(va), 'size': insn.size, 'hex': insn.bytes.hex(),
              'mnemonic': insn.mnemonic, 'operands': insn.op_str}
    assert va not in instructions or instructions[va] == record
    instructions[va] = record
    return insn


def bridge(row):
    va = int(row['va'], 16)
    data = disk(va, 5)
    assert data is not None and data[0] == 0xE9
    endpoint = va + 5 + struct.unpack('<i', data[1:])[0]
    assert endpoint == int(row['target'], 16)
    bridge_rows.append({'va': hex(va), 'target': hex(endpoint), 'hex': data.hex()})


def call(row):
    insn = instruction({'va': row['site']})
    assert insn.mnemonic == 'call'
    operand = insn.operands[0]
    target = int(row['target'], 16)
    if operand.type == X86_OP_IMM:
        assert operand.imm == target
    else:
        assert operand.type == X86_OP_MEM and not operand.mem.base and not operand.mem.index
        assert operand.mem.disp == target
    seen, chain = set(), []
    while disk(target, 1) == b'\xe9':
        assert target not in seen and len(seen) < 16
        seen.add(target)
        data = disk(target, 5)
        endpoint = target + 5 + struct.unpack('<i', data[1:])[0]
        chain.append({'va': hex(target), 'target': hex(endpoint), 'hex': data.hex()})
        target = endpoint
    assert target == int(row['implementation'], 16)
    assert [step['va'] for step in chain] == row.get('thunks', [])
    call_rows.append({'site': row['site'], 'endpoint': hex(target), 'chain': chain})


core = json.loads((HERE / 'rank_core_raw.json').read_text(encoding='utf-8'))
navigation = json.loads((HERE / 'rank_navigation_raw.json').read_text(encoding='utf-8'))
for name, value in (('rank_core_raw.json', core), ('rank_navigation_raw.json', navigation)):
    assert value['disk_sha256'] == digest
    visit(value, name)
function_rows = []
supplement_path = HERE / 'rank_supplement_raw.json'
supplement = json.loads(supplement_path.read_text(encoding='utf-8')) if supplement_path.exists() else None
if supplement is not None:
    assert supplement['disk_sha256'] == digest
    visit(supplement, 'rank_supplement_raw.json')
leaves_path = HERE / 'rank_leaves_raw.json'
leaves = json.loads(leaves_path.read_text(encoding='utf-8')) if leaves_path.exists() else None
if leaves is not None:
    assert leaves['disk_sha256'] == digest
    visit(leaves, 'rank_leaves_raw.json')
shared_path = ROOT / 'docs/逆向资料/专题/文本段键解析与预处理/证据/functions_raw.json'
shared = json.loads(shared_path.read_text(encoding='utf-8'))
assert shared['disk_sha256'] == digest
shared_rows = [row for row in shared['functions'] if row['va'] in
               ('0x8191d0', '0x819220', '0x819250', '0x819470', '0x819660')]
assert len(shared_rows) == 5
stock_path = ROOT / 'docs/逆向资料/专题/股票与交易流程/证据/stock_core.json'
stock = json.loads(stock_path.read_text(encoding='utf-8'))
assert stock['disk_sha256'] == digest
startup = next(row for row in stock['functions'] if row['va'] == '0x623cb0')
for row in shared_rows + [startup]:
    visit(row, 'reused_current_baseline/' + row['va'])
groups = [('core', core['functions']),
          ('shared_reuse', shared_rows + [startup])]
if supplement is not None:
    groups.append(('supplement', supplement['functions']))
if leaves is not None:
    groups.append(('leaves', leaves['functions']))
for role, row in [(role, row) for role, rows in groups for row in rows]:
    covered = set()
    for item in row['assembly']:
        insn = instruction(item)
        covered.update(range(insn.address, insn.address + insn.size))
    saved = {int(span['va'], 16) + n for span in row['byte_ranges'] for n in range(span['size'])}
    assert saved == covered
    declared = None
    if 'declared_chunks' in row:
        declared = {(chunk['start_va'], int(chunk['end_va'], 16) - int(chunk['start_va'], 16))
                    for chunk in row['declared_chunks']}
        chunk_saved = {(span['va'], span['size']) for span in row['chunk_byte_ranges']}
        assert declared == chunk_saved
        assert saved == {int(start, 16) + n for start, size in declared for n in range(size)}
    else:
        assert role == 'shared_reuse' and row['va'] == '0x623cb0'
    function_rows.append({'va': row['va'], 'role': role, 'bytes': len(saved),
                          'chunks': len(declared) if declared is not None else None,
                          'stored_instruction_bytes_fully_decoded': True,
                          'pseudocode_navigation': row['pseudocode']})
    for item in row['calls']:
        call(item)
for row in core['thunks'] + navigation['bridges']:
    bridge(row)
if supplement is not None:
    for row in supplement['thunks']:
        bridge(row)
if leaves is not None:
    for row in leaves['thunks']:
        bridge(row)
window_rows = []
for row in navigation['windows']:
    covered = set()
    for item in row['items']:
        assert item['declared_owner'] == row['expected_owner']
        va = int(item['va'], 16)
        covered.update(range(va, va + item['size']))
        if item['is_code']:
            instruction(item)
    assert covered == set(range(int(row['start_va'], 16), int(row['end_va'], 16)))
    window_rows.append({'start': row['start_va'], 'end': row['end_va'],
                        'owner': row['expected_owner'], 'items': len(row['items']),
                        'code_items': sum(item['is_code'] for item in row['items'])})
    for item in row['calls']:
        call(item)
strings = []
for row in navigation['data_refs']:
    if row['confirmed_c_string']:
        value = bytes.fromhex(row['string_hex'])
        assert b'\0' not in value
        assert row['string_type'] == 0
        assert row['raw']['idb_hex'] == row['raw']['disk_hex'] == value.hex() + '00'
        assert row['raw']['size'] == len(value) + 1
        strings.append({'site': row['site'], 'target': row['target'], 'hex': value.hex(),
                        'ascii': value.decode('ascii') if value.isascii() else None})
    else:
        assert row['string_hex'] is None and row['raw']['size'] == 16
for row in navigation['reused_sources']:
    assert hashlib.sha256((ROOT / row['path']).read_bytes()).hexdigest() == row['sha256']
reuse_path = HERE / 'rank_reuse_and_num_raw.json'
if reuse_path.exists():
    reuse = json.loads(reuse_path.read_text(encoding='utf-8'))
    assert reuse['num_idb_hex'] == disk(0xA2A9D8, 4).hex() == '6e756d00'
    assert reuse['consumer_idb_hex'] == disk(0x755B92, 5).hex() == '68d8a9a200'
    for row in reuse['reused_sources']:
        assert hashlib.sha256((ROOT / row['path']).read_bytes()).hexdigest() == row['sha256']
anchors = {
    0x623E8D: ('68f422a200', '启动实参直接指向Data\\Rank.kpd'),
    0x623E92: ('e8090cfeff', '启动调用Rank装载桥'),
    0x623E9A: ('c6059066a70001', '启动调用后不检测返回而继续写标记'),
    0x753FAB: ('837df07d', '短消费者遍历控件121至125'),
    0x753FED: ('6bc954', '标签槽按84字节步长寻址'),
    0x753FF0: ('81c1d059a800', '标签输入来自A859D0记录首地址'),
    0x754001: ('ff9090000000', '真实控件消费为虚槽90h，未恢复目标类型'),
    0x755A9F: ('83bd28ffffff05', '加载外循环固定5条Rank'),
    0x755AF2: ('83c001', 'RANK编号从1开始'),
    0x755B2E: ('6a40', 'label调用容量64'),
    0x755B36: ('6bc054', '加载记录步长84'),
    0x755B8C: ('8981105aa800', 'index写入记录40h'),
    0x755B92: ('68d8a9a200', 'num真实键地址push现场'),
    0x755BC9: ('8985fcfeffff', 'num解析结果成为TITLE循环界'),
    0x755BF6: ('0f8dc1000000', 'TITLE循环使用signed比较'),
    0x755C46: ('6a40', 'title调用容量64'),
    0x755C6E: ('742d', 'end键缺失时保留构造默认值'),
    0x755C97: ('8985f0feffff', 'end值写TITLE局部记录40h'),
    0x755CAD: ('81c1145aa800', '容器对象位于记录44h'),
    0x755CE4: ('6804010000', 'MORE url调用容量260'),
    0x755CE9: ('681844a800', 'MORE url目标A84418'),
    0x755D1D: ('6804010000', 'RULE url调用容量260'),
    0x755D22: ('681043a800', 'RULE url目标A84310'),
    0x7986D1: ('c74040ffffffff', 'TITLE构造end默认-1'),
    0x7986D8: ('6a40', 'TITLE构造清零64字节文本'),
    0x799882: ('e8c362e6ff', '追加先读取size'),
    0x79988C: ('e80099e6ff', '追加再读取capacity'),
    0x799893: ('731d', 'size>=capacity走增长路径'),
    0x7998AD: ('894108', '就地复制路径更新end指针'),
    0x79A4DF: ('8b410c', 'capacity使用end_capacity'),
    0x79A4E6: ('b944000000', 'capacity差值除68'),
    0x79A561: ('8b4808', '尾迭代器输入当前end指针'),
    0x79A5BF: ('8b4108', 'size使用end指针'),
    0x79A5C6: ('b944000000', 'size差值除68'),
    0x79A6D9: ('6bc044', '批量复制返回地址按68字节乘元素数'),
    0x8194A5: ('0f8d9a010000', '段扫描外层signed长度检查'),
    0x81968C: ('899090000000', '每次查键重置值游标至当前段游标'),
    0x819739: ('7505', '正常段界会终止键外层扫描'),
}
if supplement is not None:
    anchors.update({
        0x79A521: ('8b4804', '首迭代器输入begin指针'),
        0x79AE43: ('8901', '迭代器加法包装只复制所求指针'),
        0x79B0C1: ('b911000000', '增长器临时保存17DWORD值记录'),
        0x79B0C9: ('f3a5', '增长器入口直接值复制68字节'),
        0x79B11E: ('d1ee', '增长候选capacity右移一位'),
        0x79B13D: ('034598', '增长候选capacity加capacity/2'),
        0x79B268: ('894a0c', '增长后提交end_capacity'),
        0x79B277: ('894108', '增长后提交end'),
        0x79B280: ('894204', '增长后提交begin'),
        0x819A47: ('8b8890000000', '字段读取使用值游标局部副本'),
        0x819B08: ('81f980000000', '高位字节按两字节分支'),
        0x819B72: ('c60000', '复制完成后先写NUL'),
        0x819B78: ('83c101', '复制计数包含NUL'),
        0x819BE7: ('3b4d10', 'NUL写入之后才比较容量'),
        0xA1FF93: ('6878d16000', '退出数组回调入口60D178'),
        0xA1FF98: ('6a05', '退出数组数量5'),
        0xA1FF9A: ('6a54', '退出数组记录跨度84'),
        0xA1FF9C: ('68d059a800', '退出数组起点A859D0'),
    })
if leaves is not None:
    anchors.update({
        0x79C5F1: ('6bc044', '迭代器步长乘68'),
        0x79C5FC: ('8902', '迭代器推进后提交指针'),
        0x79C671: ('8b00', '解引用包装读首DWORD'),
        0x79C934: ('8908', '迭代器初始化写首DWORD'),
        0x79C966: ('2b01', '迭代器差值减输入指针'),
        0x79C969: ('b944000000', '迭代器差值除数68'),
        0x79CFAB: ('b911000000', '直接值填充复制17DWORD'),
        0x79CFB3: ('f3a5', '直接值填充执行DWORD复制'),
        0x79CF9A: ('83c044', '直接值填充目标推进68'),
        0x79D74B: ('8a45fb', '辅助返回读取调试填充局部AL，不是业务常量'),
        0x79D7D2: ('83c244', '重复构造目标推进68'),
        0x79D7D8: ('837d0c00', '重复构造计数比较零'),
        0x79D7DC: ('7612', '重复构造计数按unsigned终止'),
        0x7A1041: ('83c144', '分类析构this推进容器偏移68'),
        0x7A1044: ('e86bf9e5ff', '分类析构调用6009B4桥'),
    })
anchor_rows = []
for va, (expected, meaning) in anchors.items():
    assert disk(va, len(bytes.fromhex(expected))).hex() == expected
    assert va in instructions and instructions[va]['hex'] == expected
    anchor_rows.append({'va': hex(va), 'hex': expected, 'meaning': meaning})
num_ref = next(row for row in navigation['data_refs'] if row['site'] == '0x755b92')
assert num_ref['target'] == '0xa2a9d8'
assert num_ref['raw']['idb_hex'].startswith('6e756d00')
assert disk(0xA2A9D8, 4) == b'num\0'
num_string = {'va': '0xa2a9d8', 'hex': '6e756d00', 'size': 4,
              'consumer': '0x755b92', 'meaning': '明确NUL终止的原字节及键选择现场；不依赖IDA自动string类型'}
assert disk(0xA222F4, 14) == b'Data\\Rank.kpd\0'
startup_string = {'va': '0xa222f4', 'hex': disk(0xA222F4, 14).hex(),
                  'consumer': '0x623e8d', 'meaning': '当前PE真实启动资源实参，不从伪码名称推断'}
manifest_path = HERE.parent / '函数审阅清单.json'
manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
assert manifest['disk_sha256'] == digest
expected_partial = {'0x799860', '0x79a5f0', '0x79a6b0', '0x79b080', '0x79cd60',
                    '0xa1ff90', '0x79b520', '0x79b640', '0x79cf40', '0x79cfd0',
                    '0x79d790', '0x7a1030'}
assert len(manifest['functions']) == 31 and len(manifest['rechecked_sources']) == 1
assert {row['va'] for row in manifest['functions'] if row['status'] == '字段或调用路径局部审阅'} == expected_partial
assert sum(row['status'] == '完整函数静态审阅' for row in manifest['functions']) == 19
assert manifest['rechecked_sources'][0]['va'] == '0x819a20'
assert len(manifest['code_windows']) == 5 and len(manifest['reused_producers']) == 6
manifest_rows = []
for group in ('functions', 'rechecked_sources', 'code_windows', 'reused_producers'):
    for row in manifest[group]:
        assert all(row.get(key) for key in ('va', 'status', 'conclusion', 'unknown', 'document', 'evidence'))
        relative, separator, pointer = row['evidence'].partition('#')
        assert separator
        evidence_path = HERE.parent / relative
        selected = json.loads(evidence_path.read_text(encoding='utf-8'))
        for token in pointer.strip('/').split('/'):
            selected = selected[int(token)] if isinstance(selected, list) else selected[token]
        if group == 'code_windows':
            assert row['va'] == selected['expected_owner']
            assert row['start_va'] == selected['start_va'] and row['end_va'] == selected['end_va']
            assert row['status'] == '大型UI限定字段窗口'
            assert int(row['va'], 16) < int(row['start_va'], 16) < int(row['end_va'], 16)
        else:
            assert selected['va'] == row['va']
        assert (HERE.parent / row['document']).is_file()
        manifest_rows.append({'va': row['va'], 'group': group, 'status': row['status'],
                              'evidence': row['evidence'],
                              'evidence_sha256': hashlib.sha256(evidence_path.read_bytes()).hexdigest()})
        if group == 'code_windows':
            manifest_rows[-1].update({key: row[key] for key in ('start_va', 'end_va')})
author_documents = sorted(path for path in HERE.parent.glob('[0-9][0-9]_*.txt'))
for path in author_documents:
    assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines())
unique = {(va, size) for va, size, _ in comparisons}
result = {'status': 'PASS', 'disk_sha256': digest,
          'byte_comparisons': len(comparisons), 'unique_spans': len(unique),
          'unique_bytes': len({va + n for va, size in unique for n in range(size)}),
          'instruction_sites': len(instructions), 'functions': function_rows, 'windows': window_rows,
          'calls': call_rows, 'unique_call_sites': len({row['site'] for row in call_rows}),
          'bridges': bridge_rows, 'unique_bridges': len({row['va'] for row in bridge_rows}),
          'confirmed_strings': strings, 'navigation_without_disk': navigation_only,
          'navigation_idb_disk_mismatches': navigation_mismatches,
          'semantic_anchors': anchor_rows, 'explicit_num_string': num_string,
          'startup_resource_string': startup_string,
          'manifest_sha256': hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
          'independent_document_sha256': hashlib.sha256((HERE.parent / '独立审阅.txt').read_bytes()).hexdigest(),
          'manifest_rows': manifest_rows,
          'author_document_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                    for path in author_documents},
          'global_slots': navigation['global_slots'],
          'input_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                           for path in (HERE / 'rank_core_raw.json', HERE / 'rank_navigation_raw.json',
                                        supplement_path, leaves_path, reuse_path, shared_path, stock_path) if path.exists()},
          'scope': '字节、指令与调用静态核验；两大UI仅限定窗口，类型与业务语义仍待审阅'}
(HERE / 'independent_pe.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
lines = ['// Rank 当前磁盘独立 Capstone 解码；UI 窗口不代表整函数完成。']
for va, row in sorted(instructions.items()):
    lines.append(f"// {va:08X} {row['hex']:<30} {row['mnemonic']} {row['operands']}")
(HERE / 'independent_assembly.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(json.dumps({key: result[key] for key in ('status', 'byte_comparisons', 'unique_spans',
                                              'unique_bytes', 'instruction_sites', 'unique_call_sites',
                                              'unique_bridges')}, ensure_ascii=False))
print(json.dumps({'functions': len(function_rows), 'windows': window_rows,
                  'strings': strings, 'non_disk_navigation': len(navigation_only),
                  'navigation_mismatches': len(navigation_mismatches)}, ensure_ascii=False))
