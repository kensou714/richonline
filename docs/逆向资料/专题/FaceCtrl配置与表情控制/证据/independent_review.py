"""FaceCtrl 独立磁盘核验；不连接 IDA，不写 EXE 或资源。"""
import hashlib
import json
import struct
from collections import defaultdict
from pathlib import Path

import lzokay
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
blob = (ROOT / 'RnClient.exe').read_bytes()
sha = hashlib.sha256(blob).hexdigest()
assert sha == 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
pe = struct.unpack_from('<I', blob, 0x3C)[0]
assert blob[:2] == b'MZ' and blob[pe:pe + 4] == b'PE\0\0'
assert struct.unpack_from('<H', blob, pe + 24)[0] == 0x10B
base = struct.unpack_from('<I', blob, pe + 52)[0]
section_at = pe + 24 + struct.unpack_from('<H', blob, pe + 20)[0]
sections = [struct.unpack_from('<4I', blob, section_at + n * 40 + 8)
            for n in range(struct.unpack_from('<H', blob, pe + 6)[0])]
decoder = Cs(CS_ARCH_X86, CS_MODE_32)
decoder.detail = True
comparisons, functions, instructions, calls, bridges = [], {}, {}, [], []


def disk(va, size):
    matches = [(rva, raw_at) for _, rva, raw_size, raw_at in sections
               if base + rva <= va and va + size <= base + rva + raw_size]
    assert len(matches) == 1, (hex(va), size)
    rva, raw_at = matches[0]
    raw = blob[raw_at + va - base - rva:raw_at + va - base - rva + size]
    assert len(raw) == size
    return raw


def visit(value, origin):
    if isinstance(value, dict):
        if {'va', 'size', 'idb_hex', 'disk_hex'} <= value.keys():
            va, size = int(value['va'], 16), value['size']
            if value['disk_hex'] is not None:
                raw = disk(va, size)
                assert raw.hex() == value['idb_hex'] == value['disk_hex'], (origin, hex(va))
                assert value.get('matching', value.get('equal')) is True
                if 'sha256' in value:
                    assert hashlib.sha256(raw).hexdigest() == value['sha256']
                comparisons.append((va, size, origin))
            else:
                assert value.get('disk_backed') is False
        for key, child in value.items():
            visit(child, origin + '/' + key)
    elif isinstance(value, list):
        for n, child in enumerate(value):
            visit(child, origin + '/' + str(n))


def instruction(row):
    va = int(row['va'], 16)
    decoded = list(decoder.disasm(disk(va, 15), va, count=1))
    assert len(decoded) == 1
    insn = decoded[0]
    if 'size' in row:
        assert insn.size == row['size'], row
    if 'hex' in row:
        assert insn.bytes.hex() == row['hex'], row
    result = {'va': hex(va), 'size': insn.size, 'hex': insn.bytes.hex(),
              'mnemonic': insn.mnemonic, 'operands': insn.op_str}
    assert va not in instructions or instructions[va] == result
    instructions[va] = result
    return insn


def bridge(row):
    va = int(row['va'], 16)
    raw = disk(va, 5)
    assert raw[0] == 0xE9
    assert va + 5 + struct.unpack('<i', raw[1:])[0] == int(row['target'], 16), row
    bridges.append(row)


def call(row):
    insn = instruction({'va': row['site']})
    assert insn.mnemonic == 'call', row
    operand = insn.operands[0]
    target = int(row['target'], 16)
    if operand.type == X86_OP_IMM:
        assert operand.imm == target, row
    else:
        assert operand.type == X86_OP_MEM and not operand.mem.base and not operand.mem.index
        assert operand.mem.disp == target, row
    seen, chain = set(), []
    while disk(target, 1) == b'\xe9':
        assert target not in seen and len(seen) < 16
        seen.add(target)
        raw = disk(target, 5)
        endpoint = target + 5 + struct.unpack('<i', raw[1:])[0]
        chain.append({'va': hex(target), 'hex': raw.hex(), 'target': hex(endpoint)})
        target = endpoint
    assert target == int(row['implementation'], 16), row
    calls.append({'site': row['site'], 'endpoint': hex(target), 'chain': chain})


def function(row, source, reused=False):
    assert row['va'] not in functions
    functions[row['va']] = {'source': source, 'reused': reused}
    decoded_bytes = set()
    for item in row.get('assembly', row.get('instructions', [])):
        insn = instruction(item)
        decoded_bytes.update(range(insn.address, insn.address + insn.size))
    stored_bytes = {int(span['va'], 16) + n for span in row.get('byte_ranges', row.get('chunks', []))
                    for n in range(span['size'])}
    assert stored_bytes <= decoded_bytes, (row['va'], len(stored_bytes - decoded_bytes))
    functions[row['va']]['stored_bytes_fully_decoded'] = bool(stored_bytes)
    for item in row.get('calls', []):
        call(item)


inputs = {}
for name in ('facectrl_raw.json', 'lifecycle_raw.json', 'facectrl_context.json',
             'consumer_constructor_raw.json', 'actual_consumer_raw.json',
             'actual_consumer_vtable.json'):
    value = json.loads((HERE / name).read_text(encoding='utf-8'))
    inputs[name] = value
    assert value['disk_sha256'] == sha
    visit(value, name)
    for row in value.get('functions', []):
        function(row, name)
    for row in value.get('thunks', []) + value.get('bridges', []):
        bridge(row)

context = inputs['facectrl_context.json']
for row in context['reused_functions']:
    original = ROOT / 'docs/逆向资料' / row['source']
    assert hashlib.sha256(original.read_bytes()).hexdigest() == row['source_sha256']
    function(row['record'], row['source'], True)
for row in context['calls']:
    call(row)

reused = json.loads((HERE / 'reused_evidence.json').read_text(encoding='utf-8'))
for row in reused['functions']:
    original = ROOT / 'docs/逆向资料' / row['source']
    assert hashlib.sha256(original.read_bytes()).hexdigest() == row['source_sha256']
    visit(row['record'], 'reused_evidence/' + row['va'])
    for span in row['record'].get('byte_ranges', []):
        if 'disk_hex' not in span:
            va, size = int(span['va'], 16), span['size']
            assert disk(va, size).hex() == span['idb_hex']
            comparisons.append((va, size, 'reused_evidence/idb_only/' + row['va']))
    if row['va'] not in functions:
        function(row['record'], row['source'], True)

vtable = inputs['actual_consumer_vtable.json']
assert disk(0x6FC035, 6).hex() == 'c7002071a200'
for row in vtable['slots']:
    assert struct.unpack('<I', disk(0xA27120 + int(row['offset'], 16), 4))[0] == int(row['target'], 16)
assert vtable['selected_offset'] == '0x10' and vtable['implementation'] == '0x73a590'

# 文本与容器旧来源缺逐块磁盘字节；本轮另核完整的文本过滤来源，以下为磁盘补证。
copy_source = ROOT / 'docs/逆向资料/专题/文本与容器/证据/parser_kpd_functions.json'
copy_raw = disk(0x8198E0, 320)
copy_instructions = list(decoder.disasm(copy_raw, 0x8198E0))
assert copy_instructions[-1].address == 0x819A1D
for item in copy_instructions:
    instruction({'va': hex(item.address), 'hex': item.bytes.hex(), 'size': item.size})
copy_evidence = {'va': '0x8198e0', 'size': 320, 'disk_hex': copy_raw.hex(),
                 'disk_sha256': hashlib.sha256(copy_raw).hexdigest(),
                 'prior_source': str(copy_source.relative_to(ROOT)),
                 'prior_source_sha256': hashlib.sha256(copy_source.read_bytes()).hexdigest(),
                 'scope': '当前 PE 补验，未计 IDB/disk 比较或新增函数覆盖'}

anchors = {
    'constructor_only_pointer_zero': (0x64CE61, 'c70000000000'),
    'destructor_pointer_zero': (0x64CEA6, 'c70100000000'),
    'count_reset': (0x64CF83, 'c7410400000000'),
    'record_stride': (0x64CFC2, '69c908010000'),
    'replacement_pointer_store': (0x64CFE0, '8902'),
    'ctrl_missing_stop': (0x64D090, 'eb27'),
    'ctrl_copy_size': (0x64D092, '6a08'),
    'ctrl_slot_address': (0x64D0A7, '8d54c808'),
    'ctrl_repeat_without_capacity_gate': (0x64D0B7, 'eba0'),
    'ctrl_count_store': (0x64D0CA, '894c0204'),
    'strlen_before_null_test': (0x64D1A6, 'e88231fcff'),
    'late_null_test': (0x64D1B1, '837d0c00'),
    'strstr_call': (0x64D22C, 'e8c431fcff'),
    'equal_offset_does_not_replace': (0x64D246, '7d1d'),
    'sentinel_face_still_selected': (0x64D259, '894dec'),
    'sentinel_face_suppresses_dispatch': (0x64D26C, '837decff'),
    'message_update_mask_10': (0x64D272, 'c745d810000000'),
    'message_argument': (0x64D27C, '8945dc'),
    'message_selected_face': (0x64D282, '894de0'),
    'message_factory_4f': (0x64D289, '6a4f'),
    'copy_loop_constant_true': (0x819913, 'b801000000'),
    'copy_high_byte_pair': (0x819926, '81fa80000000'),
    'copy_lf_terminator': (0x819977, '83f80a'),
    'copy_lf_counts_nul': (0x81997F, '83c101'),
    'copy_nul_before_assert': (0x819988, 'c60200'),
    'copy_post_write_size_comparison': (0x8199F4, '3b550c'),
    'copy_assert_only_if_greater': (0x8199F7, '7e17'),
    'copy_assert_call': (0x819A08, 'e8ac23dfff'),
    'scalar_delete_flag': (0x629179, '83e001'),
    'consumer_input_flags': (0x73A5DF, '8b02'),
    'consumer_face_flag': (0x73B694, '83e210'),
    'consumer_slot_limit_400': (0x73B6AF, '817de090010000'),
    'consumer_actor_id_comparison': (0x73B70C, '3b4204'),
    'consumer_face_id_read': (0x73B714, '8b5108'),
    'consumer_face_stride': (0x73B726, '69c01c020000'),
    'consumer_face_object_base': (0x73B72F, '8d4c0268'),
    'consumer_face_apply': (0x73B733, 'e8b267ecff'),
    'consumer_tick_store': (0x73B757, '894c8254'),
    'consumer_first_match_break': (0x73B75B, 'eb05'),
    'shutdown_delete_flag_one': (0x6241ED, '6a01'),
    'shutdown_global_clear': (0x624209, 'c7053c67a70000000000'),
    'factory_create_registration': (0x6E6699, 'c782840100006b1b6000'),
    'factory_destroy_registration': (0x6E66A6, 'c78004040000a7846000'),
    'manager_create_slot_call': (0x6E3BD2, 'ff548148'),
    'manager_created_instance_store': (0x6E3BEC, '89441104'),
    'dispatcher_missing_instance_skip': (0x6E4671, '743a'),
    'dispatcher_vtable_slot_10': (0x6E46A3, 'ff5010'),
    'factory_allocation_93c': (0x6E8F80, '683c090000'),
    'factory_constructor_call': (0x6E8FA0, 'e8a0f7f1ff'),
    'consumer_ctor_array_count': (0x6FC045, '6a04'),
    'consumer_ctor_array_stride': (0x6FC047, '681c020000'),
    'consumer_ctor_array_base': (0x6FC04F, '83c168'),
}
for label, (va, expected) in anchors.items():
    assert disk(va, len(bytes.fromhex(expected))).hex() == expected, label

# 发送体从 -0x28 开始，三个 DWORD 是更新位、角色标识和表情编号。
message_writes = []
for va, row in instructions.items():
    if 0x64D180 <= va < 0x64D297 and row['mnemonic'] == 'mov':
        insn = next(decoder.disasm(bytes.fromhex(row['hex']), va))
        if insn.operands and insn.operands[0].type == X86_OP_MEM:
            operand = insn.operands[0]
            if insn.reg_name(operand.mem.base) == 'ebp' and -0x28 <= operand.mem.disp < -0x18:
                message_writes.append(operand.mem.disp)
assert message_writes == [-0x28, -0x24, -0x20]

packet_alias_loads = []
for va, row in instructions.items():
    if 0x73A590 <= va < 0x73B8AD:
        insn = next(decoder.disasm(bytes.fromhex(row['hex']), va))
        for operand in insn.operands[1:]:
            if (operand.type == X86_OP_MEM and insn.reg_name(operand.mem.base) == 'ebp'
                    and operand.mem.disp == -0x10):
                packet_alias_loads.append(hex(va))
assert packet_alias_loads == ['0x73a5dc', '0x73b707', '0x73b711']

extra_bridges = []
for va, endpoint in ((0x601B6B, 0x6E8F50), (0x608745, 0x6FC000),
                     (0x604050, 0x629160), (0x6084A7, 0x6ECD70)):
    row = {'va': hex(va), 'target': hex(endpoint)}
    bridge(row)
    extra_bridges.append(dict(row, disk_hex=disk(va, 5).hex()))

# 资源词法核验只承认实际字节，不由候选中文解码推导程序编码。
resource = json.loads((HERE / 'resources.json').read_text(encoding='utf-8'))
raw = (ROOT / resource['path']).read_bytes()
assert len(raw) == resource['source_size']
assert hashlib.sha256(raw).hexdigest() == resource['source_sha256']
packed = bytes((byte - raw[0]) % 256 for byte in raw[1:])
assert raw[0] == resource['key']
length, compressed_size = struct.unpack_from('<II', packed)
compressed = packed[8:]
plain = lzokay.decompress(compressed, length)
assert compressed_size == len(compressed) == resource['compressed_size']
for data, label in ((packed, 'packed'), (compressed, 'compressed'), (plain, 'decoded')):
    assert len(data) == resource[label + '_size']
    assert hashlib.sha256(data).hexdigest() == resource[label + '_sha256']
assert length == len(plain)
assert b''.join(bytes.fromhex(row['bytes']) for row in resource['lines']) == plain
for row in resource['lines']:
    data = bytes.fromhex(row['bytes'])
    assert len(data) == row['size'] and plain[row['offset']:row['offset'] + row['size']] == data
for row in resource['entries']:
    key, value = bytes.fromhex(row['key_hex']), bytes.fromhex(row['value_hex'])
    assert plain[row['key_offset']:row['key_offset'] + len(key)] == key
    assert plain[row['value_offset']:row['value_offset'] + len(value)] == value
    assert plain[row['value_offset'] - 1] == ord('=')

groups = defaultdict(list)
for row in resource['entries']:
    groups[row['section_index']].append(row)
resource_layout = []
for section, rows in sorted(groups.items()):
    assert [row['key_ascii'] for row in rows] == ['face'] + [f'ctrl{n}' for n in range(5)]
    assert bytes.fromhex(rows[0]['value_hex']).strip() == str(section + 1).encode('ascii')
    sizes = []
    for row in rows[1:]:
        value = bytes.fromhex(row['value_hex']).lstrip(b' \t')
        assert value.hex() == row['leading_space_trimmed_value_hex']
        assert b'\0' not in value and b'\n' not in value and b'`n' not in value
        # 当前资源高位字节均有第二字节，未涉及损坏资源的跨行读取。
        n = 0
        while n < len(value):
            n += 2 if value[n] >= 0x80 else 1
            assert n <= len(value)
        assert len(value) + 1 <= 8
        sizes.append(len(value))
    resource_layout.append({'section': section, 'face': section + 1,
                            'ctrl_count': len(sizes), 'output_byte_lengths': sizes})

unique = {(va, size) for va, size, _ in comparisons}
review_path = HERE.parent / 'function_review.json'
review = json.loads(review_path.read_text(encoding='utf-8'))
assert len(review['functions']) == 22
assert {row['va'] for row in review['functions']} == set(functions)
review_levels = defaultdict(int)
for row in review['functions']:
    assert row['reused'] == functions[row['va']]['reused']
    assert row['conclusion'] and row['unknown'] and row['range_limit']
    review_levels[row['status']] += 1
    for evidence in row['evidence']:
        path = HERE.parent / evidence['path']
        if not path.is_file():
            path = ROOT / 'docs/逆向资料' / evidence['path']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == evidence['sha256']
        assert evidence['entry'] == row['va']
    for span in row['original_byte_ranges']:
        saved_raw = disk(int(span['va'], 16), span['size'])
        assert saved_raw.hex() == span['idb_hex']
        if span.get('disk_hex') is not None:
            assert saved_raw.hex() == span['disk_hex']
    if row['declared_chunks']:
        saved = {(span['va'], span['size']) for span in row['original_byte_ranges']}
        declared = {(chunk['start_va'], int(chunk['end_va'], 16) - int(chunk['start_va'], 16))
                    for chunk in row['declared_chunks']}
        assert declared == saved
assert review_levels['已审阅'] == 5 and review_levels['局部审阅'] == 2
assert next(row for row in review['functions'] if row['va'] == '0x6e8f50')['status'] == '复用主范围局部审阅'
assert {row['va'] for row in review['followup']} == {'0x797800', '0x6ecd70'}
result = {'status': 'PASS', 'disk_sha256': sha, 'functions': functions,
          'byte_comparisons': len(comparisons), 'unique_spans': len(unique),
          'unique_bytes': len({va + n for va, size in unique for n in range(size)}),
          'instruction_sites': len(instructions), 'calls': len(calls),
          'unique_call_sites': len({row['site'] for row in calls}),
          'bridge_rows': len(bridges), 'unique_bridges': len({row['va'] for row in bridges}),
          'resolved_calls': calls,
          'resource': {'source_size': len(raw), 'decoded_size': len(plain),
                       'sections': len(resource['sections']), 'entries': len(resource['entries']),
                       'layout': resource_layout},
          'semantic_anchors': {label: hex(row[0]) for label, row in anchors.items()},
          'message_business_writes': message_writes, 'copy_disk_evidence': copy_evidence,
          'consumer_packet_alias_loads': packet_alias_loads,
          'extra_bridges': extra_bridges,
          'final_review_levels': dict(review_levels),
          'final_review_sha256': hashlib.sha256(review_path.read_bytes()).hexdigest(),
          'scope': '磁盘字节、调用链、核心语义锚点和资源边界核验；未运行客户端'}
(HERE / 'independent_local.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
lines = ['// 当前磁盘独立 Capstone 解码；复用函数不计新增覆盖。']
for va, row in sorted(instructions.items()):
    lines.append(f"// {va:08X} {row['hex']:<30} {row['mnemonic']} {row['operands']}")
(HERE / 'independent_assembly.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(json.dumps({key: result[key] for key in ('status', 'byte_comparisons', 'instruction_sites',
                                             'calls', 'unique_bridges', 'resource')}, ensure_ascii=False))
