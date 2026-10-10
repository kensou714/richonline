"""独立 PE 映射、Capstone 解码及原证来源核验；不连接或改写 IDA。"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
IMAGE = (ROOT / 'RnClient.exe').read_bytes()
HASH = hashlib.sha256(IMAGE).hexdigest()
assert HASH == 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
pe = struct.unpack_from('<I', IMAGE, 0x3C)[0]
assert IMAGE[:2] == b'MZ' and IMAGE[pe:pe + 4] == b'PE\0\0'
assert struct.unpack_from('<H', IMAGE, pe + 24)[0] == 0x10B
base = struct.unpack_from('<I', IMAGE, pe + 52)[0]
table = pe + 24 + struct.unpack_from('<H', IMAGE, pe + 20)[0]
sections = [struct.unpack_from('<4I', IMAGE, table + n * 40 + 8)
            for n in range(struct.unpack_from('<H', IMAGE, pe + 6)[0])]
decoder = Cs(CS_ARCH_X86, CS_MODE_32)
decoder.detail = True
compares, instructions, functions, calls, bridges, source_hashes = [], {}, {}, [], [], []
resolved_calls, producer_rows = [], []


def disk(va, size):
    found = [(rva, off) for _, rva, raw_size, off in sections
             if base + rva <= va and va + size <= base + rva + raw_size]
    assert len(found) == 1, (hex(va), size)
    rva, off = found[0]
    data = IMAGE[off + va - base - rva:off + va - base - rva + size]
    assert len(data) == size
    return data


def compare(row, origin):
    va, size = int(row['va'], 16), row['size']
    data = disk(va, size)
    assert data.hex() == row['idb_hex'] == row['disk_hex'], (origin, hex(va))
    assert row['matching'] is True
    compares.append((va, size, origin))


def visit(value, origin):
    if isinstance(value, dict):
        if {'va', 'size', 'idb_hex', 'disk_hex', 'matching'} <= value.keys():
            compare(value, origin)
        for key, child in value.items():
            visit(child, origin + '/' + key)
    elif isinstance(value, list):
        for n, child in enumerate(value):
            visit(child, origin + '/' + str(n))


def decode_row(row, origin):
    va = int(row['va'], 16)
    decoded = list(decoder.disasm(disk(va, 15), va, count=1))
    assert len(decoded) == 1, (origin, hex(va))
    insn = decoded[0]
    if 'size' in row:
        assert insn.size == row['size'], (origin, hex(va), insn.size, row['size'])
    prior = instructions.get(va)
    rendered = {'va': hex(va), 'size': insn.size,
                'hex': insn.bytes.hex(), 'mnemonic': insn.mnemonic,
                'operands': insn.op_str}
    assert prior is None or prior == rendered
    instructions[va] = rendered


FILES = ('consumers_raw.json', 'rechecked_raw.json', 'dependencies_raw.json',
         'tail_picker_raw.json', 'windows_and_incoming.json', 'window_roots_raw.json')
inputs = {}
for name in FILES:
    value = json.loads((HERE / name).read_text(encoding='utf-8'))
    inputs[name] = value
    if 'disk_sha256' in value:
        assert value['disk_sha256'] == HASH
    visit(value, name)
    for f in value.get('functions', []):
        assert f['va'] not in functions
        functions[f['va']] = f
        for row in f['assembly']:
            decode_row(row, name)
        for row in f['calls']:
            va, target = int(row['site'], 16), int(row['target'], 16)
            insn = next(decoder.disasm(disk(va, 15), va, count=1))
            assert insn.mnemonic == 'call'
            operand = insn.operands[0]
            if operand.type == X86_OP_IMM:
                assert operand.imm == target, (row, insn.op_str)
            else:
                assert operand.type == X86_OP_MEM and not operand.mem.base and not operand.mem.index
                assert operand.mem.disp == target, (row, insn.op_str)
            calls.append(row)
    for window in value.get('windows', []):
        assert '未声明' in window['status']
        for row in window['items']:
            if row['is_code']:
                decode_row(row, name)
        for row in window['calls']:
            va, target = int(row['site'], 16), int(row['target'], 16)
            insn = next(decoder.disasm(disk(va, 15), va, count=1))
            assert insn.mnemonic == 'call' and insn.operands[0].imm == target
            calls.append(row)
    for row in value.get('bridges', []) + value.get('thunks', []):
        va = int(row['va'], 16)
        data = disk(va, 5)
        assert data[0] == 0xE9
        assert va + 5 + struct.unpack('<i', data[1:])[0] == int(row['target'], 16)
        bridges.append(row)

for row in calls:
    target = int(row['target'], 16)
    seen, chain = set(), []
    while disk(target, 1) == b'\xe9':
        assert target not in seen and len(seen) < 16, row
        seen.add(target)
        data = disk(target, 5)
        endpoint = target + 5 + struct.unpack('<i', data[1:])[0]
        chain.append({'va': hex(target), 'hex': data.hex(), 'target': hex(endpoint)})
        target = endpoint
    assert target == int(row['implementation'], 16), row
    resolved_calls.append({'site': row['site'], 'endpoint': hex(target), 'chain': chain})

for value in (inputs['windows_and_incoming.json'],
              json.loads((HERE / 'dependency_sources.json').read_text(encoding='utf-8'))):
    for row in value.get('reused_sources', value.get('sources', [])):
        path = ROOT / row['path']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row['sha256'], str(path)
        source_hashes.append(row)

old_source = ROOT / 'docs/逆向资料/专题/地图与路径/证据/map_runtime_core.json'
old = json.loads(old_source.read_text(encoding='utf-8'))
for function in old['函数']:
    if function['地址'] not in ('0x7df010', '0x7ed0e0'):
        continue
    for row in function['完整汇编']:
        va = int(row['地址'], 16)
        if function['地址'] == '0x7df010' and not 0x7DF6F1 <= va < 0x7DF828:
            continue
        raw = row['字节核验']
        translated = {'va': row['地址'], 'size': len(bytes.fromhex(raw['IDB字节'])),
                      'idb_hex': raw['IDB字节'], 'disk_hex': raw['磁盘字节'],
                      'matching': raw['匹配']}
        compare(translated, '旧生产者/' + function['地址'])
        decode_row(translated, '旧生产者/' + function['地址'])
        producer_rows.append(row['地址'])

teach_source = ROOT / 'docs/逆向资料/专题/TeachMode对象与消费者/证据/teachmode_raw.json'
teach = json.loads(teach_source.read_text(encoding='utf-8'))
host_rows = []


def host_visit(value):
    if isinstance(value, dict):
        if value.get('va') == '0x7f3c70' and 'instructions' in value:
            for row in value['instructions']:
                if int(row['va'], 16) in (0x7F3CA4, 0x7F416A, 0x7F416D):
                    assert disk(int(row['va'], 16), row['size']).hex() == row['hex']
                    decode_row(row, '角色宿主调用现场')
                    host_rows.append(row['va'])
        for child in value.values():
            host_visit(child)
    elif isinstance(value, list):
        for child in value:
            host_visit(child)


host_visit(teach)
assert len(host_rows) == 3
supplemental_bridges = []
for va, target in ((0x60633C, 0x7ED0E0), (0x60F14E, 0x63F3C0)):
    raw = disk(va, 5)
    assert raw[0] == 0xE9 and va + 5 + struct.unpack('<i', raw[1:])[0] == target
    supplemental_bridges.append({'va': hex(va), 'hex': raw.hex(), 'target': hex(target)})


def require(va, mnemonic, operands):
    actual = instructions[va]
    assert (actual['mnemonic'], actual['operands']) == (mnemonic, operands), actual


require(0x7E8257, 'mov', 'eax, dword ptr [ecx + 4]')
require(0x7E825A, 'sub', 'eax, dword ptr [edx + 0xc]')
require(0x7E8262, 'movsx', 'ecx, word ptr [edx + 2]')
require(0x7E8266, 'sub', 'eax, ecx')
require(0x7E826F, 'mov', 'ecx, dword ptr [edx]')
require(0x7E8271, 'sub', 'ecx, dword ptr [eax + 8]')
require(0x7E8279, 'movsx', 'edx, word ptr [eax]')
require(0x7E827C, 'sub', 'ecx, edx')
require(0x7E8282, 'mov', 'ecx, dword ptr [eax + 0x10]')

for va, mnemonic, operands in (
    (0x63F3D3, 'cmp', 'dword ptr [eax + 0x98], 0'),
    (0x63F3DA, 'setg', 'cl'),
    (0x7ECF53, 'cmp', 'dword ptr [eax], 0'),
    (0x7ECF56, 'sete', 'cl'),
    (0x7E8896, 'mov', 'ecx, dword ptr [eax + 0x10]'),
    (0x7E88A6, 'xor', 'eax, eax'),
    (0x7E116F, 'cmp', 'edx, dword ptr [ecx + 0x74]'),
    (0x7E118E, 'mov', 'eax, dword ptr [edx + eax*8 + 4]'),
    (0x7E11E7, 'cmp', 'eax, dword ptr [edx + 0x8c]'),
    (0x7E120A, 'mov', 'dword ptr [ebp + edx*4 - 0x414], eax'),
    (0x7E1238, 'shl', 'edx, 2'),
    (0x7E1253, 'mov', 'dword ptr [eax + 0xa0], ecx'),
    (0x7E129F, 'jge', '0x7e12ca'),
    (0x7E12F1, 'cmp', 'edx, dword ptr [ecx + 0x94]'),
    (0x7E1314, 'mov', 'dword ptr [ebp + ecx*4 - 0x414], eax'),
    (0x7E1342, 'shl', 'ecx, 2'),
    (0x7E135D, 'mov', 'dword ptr [edx + 0xa8], eax'),
    (0x7E13A9, 'jge', '0x7e13d4'),
    (0x7E1436, 'cdq', ''),
    (0x7E1437, 'idiv', 'dword ptr [ecx + 0x9c]'),
    (0x7E1440, 'mov', 'ecx, dword ptr [eax + 0xa0]'),
    (0x7E1476, 'cdq', ''),
    (0x7E1477, 'idiv', 'dword ptr [ecx + 0xa4]'),
    (0x7E1480, 'mov', 'ecx, dword ptr [eax + 0xa8]'),
    (0x7ED105, 'push', '0x1c'),
    (0x7ED11B, 'mov', 'dword ptr [ecx + 0x14], 0'),
    (0x7ED125, 'mov', 'dword ptr [edx + 0x18], 0'),
    (0x7DF7B3, 'mov', 'ecx, dword ptr [ebp - 0x13c]'),
    (0x7DF7BF, 'mov', 'edx, dword ptr [ebp - 0x138]'),
    (0x7DF7CB, 'mov', 'eax, dword ptr [ebp - 0x134]'),
    (0x7DF7D7, 'mov', 'ecx, dword ptr [ebp - 0x130]'),
    (0x7F3CA4, 'mov', 'dword ptr [ebp - 0x10], ecx'),
    (0x7F416A, 'mov', 'ecx, dword ptr [ebp - 0x10]'),
    (0x7F416D, 'call', '0x60f14e'),
):
    require(va, mnemonic, operands)

rtc_header = struct.unpack('<II', disk(0x7E13FA, 8))
rtc_array = struct.unpack('<iII', disk(0x7E1402, 12))
rtc_name = disk(rtc_array[2], 10)
assert rtc_header == (1, 0x7E1402)
assert rtc_array == (-0x414, 0x400, 0x7E140E)
assert rtc_name == b'iRatioAry\0'
rtc_result = {'header_va': '0x7e13fa', 'header_hex': disk(0x7E13FA, 8).hex(),
              'array_va': '0x7e1402', 'array_hex': disk(0x7E1402, 12).hex(),
              'offset': rtc_array[0], 'size': rtc_array[1], 'name': 'iRatioAry'}

unique = {(va, size) for va, size, _ in compares}
bytes_seen = {va + offset for va, size in unique for offset in range(size)}
result = {'status': 'PASS', 'execution': 'offline PE + Capstone 5',
          'disk_sha256': HASH, 'functions': list(functions),
          'byte_comparisons': len(compares), 'unique_spans': len(unique),
          'unique_bytes': len(bytes_seen), 'instruction_sites': len(instructions),
          'calls': len(calls), 'bridges': len(bridges),
          'unique_bridges': len({row['va'] for row in bridges}),
          'resolved_calls': resolved_calls, 'rtc_array': rtc_result,
          'reused_producer_instruction_sites': len(producer_rows),
          'host_callsite_instruction_sites': host_rows,
          'supplemental_bridges': supplemental_bridges,
          'reused_source_hashes': source_hashes,
          'scope': '保存块与指令及关键公式核验；并非所有函数语义完成或运行时验收'}
(HERE / 'independent_local.json').write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
assembly = ['// 独立 Capstone 磁盘解码；导航窗不声明函数。']
for va in sorted(instructions):
    row = instructions[va]
    assembly.append(f"// {va:08X} {row['hex']:<30} {row['mnemonic']} {row['operands']}")
(HERE / 'independent_assembly.txt').write_text('\n'.join(assembly) + '\n', encoding='utf-8')
print(json.dumps({key: result[key] for key in ('status', 'byte_comparisons', 'unique_spans',
                                             'unique_bytes', 'instruction_sites', 'calls',
                                             'unique_bridges')}, ensure_ascii=False))
