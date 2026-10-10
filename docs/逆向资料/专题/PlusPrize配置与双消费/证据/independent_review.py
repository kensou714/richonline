"""PlusPrize 当前PE与资源独立核验；不调用IDA，不改客户端或作者原证。"""
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

import lzokay
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
TOPICS = ROOT / 'docs/逆向资料/专题'
BASELINE = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
source = (ROOT / 'RnClient.exe').read_bytes()
assert hashlib.sha256(source).hexdigest() == BASELINE
pe = struct.unpack_from('<I', source, 60)[0]
assert source[:2] == b'MZ' and source[pe:pe + 4] == b'PE\0\0'
assert struct.unpack_from('<H', source, pe + 24)[0] == 0x10B
base = struct.unpack_from('<I', source, pe + 52)[0]
section_at = pe + 24 + struct.unpack_from('<H', source, pe + 20)[0]
sections = [struct.unpack_from('<4I', source, section_at + n * 40 + 8)
            for n in range(struct.unpack_from('<H', source, pe + 6)[0])]
decoder = Cs(CS_ARCH_X86, CS_MODE_32)
decoder.detail = True
comparisons, instructions, functions, calls, bridges, navigation_only = [], {}, [], {}, {}, []
input_hashes = {}


def load(path):
    blob = path.read_bytes()
    input_hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(blob).hexdigest()
    return json.loads(blob)


def disk(va, size):
    matches = [(rva, offset) for _, rva, raw_size, offset in sections
               if base + rva <= va and va + size <= base + rva + raw_size]
    if not matches:
        return None
    assert len(matches) == 1
    rva, offset = matches[0]
    result = source[offset + va - base - rva:offset + va - base - rva + size]
    assert len(result) == size
    return result


def compare(row, origin):
    va, size = int(row['va'], 16), row['size']
    actual = disk(va, size)
    assert actual is not None and actual.hex() == row['disk_hex'] == row['idb_hex']
    assert row.get('matching', row.get('equal')) is True
    if 'sha256' in row:
        assert hashlib.sha256(actual).hexdigest() == row['sha256']
    comparisons.append((va, size, origin))


def instruction(row):
    va = int(row['va'], 16)
    item = next(decoder.disasm(disk(va, 15), va, count=1))
    if 'size' in row:
        assert item.size == row['size']
    if 'hex' in row:
        assert item.bytes.hex() == row['hex']
    record = dict(va=hex(va), size=item.size, hex=item.bytes.hex(),
                  mnemonic=item.mnemonic, operands=item.op_str)
    assert va not in instructions or record == instructions[va]
    instructions[va] = record
    return item


def resolve(target):
    chain = []
    while disk(target, 1) == b'\xe9':
        assert target not in chain and len(chain) < 16
        chain.append(target)
        raw = disk(target, 5)
        endpoint = target + 5 + struct.unpack_from('<i', raw, 1)[0]
        bridges[target] = dict(va=hex(target), target=hex(endpoint), hex=raw.hex())
        target = endpoint
    return target, chain


def call(row):
    item = instruction(dict(va=row['site']))
    assert item.mnemonic == 'call'
    target = int(row['target'], 16)
    op = item.operands[0]
    assert ((op.type == X86_OP_IMM and op.imm == target) or
            (op.type == X86_OP_MEM and op.mem.base == op.mem.index == 0 and op.mem.disp == target))
    endpoint, chain = resolve(target)
    assert endpoint == int(row['implementation'], 16)
    assert [hex(x) for x in chain] == row.get('thunks', row.get('chain'))
    calls[int(row['site'], 16)] = dict(site=row['site'], target=row['target'],
                                      implementation=hex(endpoint), chain=[hex(x) for x in chain])


def function(row, origin):
    spans = row.get('byte_ranges', row.get('chunks'))
    for span in spans:
        compare(span, origin)
    covered = set()
    for saved in row.get('assembly', row.get('instructions')):
        item = instruction(saved)
        covered.update(range(item.address, item.address + item.size))
    stored = {int(span['va'], 16) + n for span in spans for n in range(span['size'])}
    assert stored == covered
    if 'declared_chunks' in row:
        declared = {(chunk['start_va'], int(chunk['end_va'], 16) - int(chunk['start_va'], 16))
                    for chunk in row['declared_chunks']}
        assert declared == {(span['va'], span['size']) for span in row['chunk_byte_ranges']}
        for span in row['chunk_byte_ranges']:
            compare(span, origin + '/declared')
    else:
        declared = {(span['va'], span['size']) for span in row['chunks']}
    assert stored == {int(start, 16) + n for start, size in declared for n in range(size)}
    if 'calls' in row:
        for item in row['calls']:
            call(item)
    else:
        for item in row['outgoing']:
            if item['iscode'] and item['kind'] in (16, 17):
                call(item)
    functions.append(dict(va=row['va'], origin=origin, bytes=len(stored), chunks=len(declared),
                          saved_declared_bytes_fully_decoded=True))


raw = load(HERE / 'plusprize_raw.json')
context = load(HERE / 'plusprize_context.json')
assert raw['disk_sha256'] == context['disk_sha256'] == BASELINE
assert len(raw['functions']) == 7
assert set(context['seeds']) == {row['va'] for row in raw['functions']}
for row in raw['functions']:
    function(row, 'plusprize_raw.json')
for row in raw['thunks'] + context['bridges']:
    compare(row, 'saved_bridge')
    endpoint, chain = resolve(int(row['va'], 16))
    assert chain and bridges[int(row['va'], 16)]['target'] == row['target']
for row in context['calls']:
    call(row)
for row in context['reuse_sources']:
    path = ROOT / 'docs/逆向资料' / row['path']
    assert hashlib.sha256(path.read_bytes()).hexdigest() == row['sha256']
    load(path)
for row in context['reused_functions']:
    path = ROOT / 'docs/逆向资料' / row['source']
    original = json.loads(path.read_bytes())
    assert original['disk_sha256'] == BASELINE
    assert next(f for f in original['functions'] if f['va'] == row['va']) == row['record']
    function(row['record'], 'context_reuse/' + row['va'])
helpers = load(HERE / 'consumer_helpers.json')
assert helpers['disk_sha256'] == BASELINE
assert {row['va'] for row in helpers['functions']} == {'0x7d6550', '0x7d7ed0'}
for row in helpers['functions']:
    function(row, 'consumer_helpers.json')
reuse = load(HERE / 'reused_evidence.json')
for row in reuse['sources']:
    path = ROOT / 'docs/逆向资料' / row['path']
    assert hashlib.sha256(path.read_bytes()).hexdigest() == row['sha256']
for row in reuse['functions']:
    original = load(ROOT / 'docs/逆向资料' / row['source'])
    assert input_hashes['docs/逆向资料/' + row['source']] == row['source_sha256']
    assert original['disk_sha256'] == BASELINE
    assert next(f for f in original['functions'] if f['va'] == row['va']) == row['record']
    function(row['record'], 'manifest_reuse/' + row['va'])
for row in reuse['bridges']:
    original = load(ROOT / 'docs/逆向资料' / row['source'])
    saved = row['record']
    assert saved in original['thunks']
    compare(saved, 'reused_source_bridge')
    resolve(int(saved['va'], 16))
    assert bridges[int(saved['va'], 16)]['target'] == saved['target']
compare(context['singleton'], 'singleton_pointer_slot')
strings = []
for row in context['strings']:
    compare(row, 'C_string')
    assert bytes.fromhex(row['value_hex']) + b'\0' == bytes.fromhex(row['disk_hex'])
    assert b'\0' not in bytes.fromhex(row['value_hex'])
    strings.append(dict(va=row['va'], hex=row['value_hex'], ascii=bytes.fromhex(row['value_hex']).decode('ascii')))
for row in context['rejected_string_candidates']:
    compare(row, 'rejected_string_navigation')
    assert bytes.fromhex(row['value_hex']) + b'\0' != bytes.fromhex(row['disk_hex'])

parser = load(TOPICS / '文本段键解析与预处理/证据/functions_raw.json')
assert parser['disk_sha256'] == BASELINE
for row in parser['functions']:
    if row['va'] in ('0x8191d0', '0x819220', '0x819250', '0x819470', '0x819660'):
        function(row, 'shared_text_parser')
line_parser = load(TOPICS / '大厅URL读取与缓冲契约/证据/functions_raw.json')
assert line_parser['disk_sha256'] == BASELINE
function(next(row for row in line_parser['functions'] if row['va'] == '0x8198e0'), 'shared_line_parser')

# 引用只验证现场指令的目标，不把外围调用者升级为完整函数审阅。
for row in context['data_references'] + context['singleton']['incoming']:
    item = instruction(dict(va=row['site']))
    target = int(row['target'], 16)
    assert any((op.type == X86_OP_IMM and op.imm == target) or
               (op.type == X86_OP_MEM and op.mem.base == op.mem.index == 0 and op.mem.disp == target)
               for op in item.operands)
    navigation_only.append(dict(site=row['site'], target=row['target'], owner=row['owner'], kind='data'))
for owner, rows in context['incoming'].items():
    for row in rows:
        assert row['iscode']
        item = instruction(dict(va=row['site']))
        assert item.mnemonic in ('call', 'jmp')
        assert item.operands[0].type == X86_OP_IMM and item.operands[0].imm == int(row['target'], 16)
        assert resolve(int(row['target'], 16))[0] == int(owner, 16)
        navigation_only.append(dict(site=row['site'], target=row['target'], owner=row['owner'], kind='code'))

anchors = {
    0x628D34: '6a10', 0x623FBE: '68a023a200', 0x6244AD: 'e84b08feff',
    0x7FDF4C: '8801', 0x7FDF87: '894104', 0x7FDFC3: '894108', 0x7FDFFF: '89410c',
    0x7D036F: 'd95dec', 0x7D0372: 'db0580cea800', 0x7D0378: 'd95de8',
    0x7D038D: 'd88481bc050000', 0x7D039A: 'd99c90bc050000', 0x7D03B8: 'c20800',
    0x7D0487: 'd9059033a200', 0x7D04A6: '3b058ccea800',
    0x7D04D2: 'c781fc05000000000000', 0x7D0562: 'd980fc050000',
    0xA15119: '83e0fe', 0xA15127: '83e0fd', 0xA1513F: '83e0fe', 0xA1514D: '83e0fd',
    0x7D6561: '8b00', 0x7D7EE4: '8a80480e0000',
}
for va, expected in anchors.items():
    assert instructions[va]['hex'] == expected
assert disk(0xA23390, 4) == b'\0' * 4
startup_string = b'Data\\PlusPrize.kpd\0'
assert disk(0xA223A0, len(startup_string)) == startup_string
float_sequence = [(row['va'], row['mnemonic'], row['hex']) for va, row in sorted(instructions.items())
                  if 0x7D02B0 <= va < 0x7D03BB and row['mnemonic'].startswith('f')]
assert [row[1] for row in float_sequence] == ['fstp', 'fild', 'fstp', 'fld', 'fmul', 'fstp', 'fld', 'fadd', 'fstp']
assert resolve(0x604CFD)[0] == 0x91FC60

resource = (ROOT / 'Data/PlusPrize.kpd').read_bytes()
header = bytes((byte - resource[0]) % 256 for byte in resource[1:9])
plain_size, compressed_size = struct.unpack('<II', header)
assert 0 < plain_size < 16 * 1024 * 1024
assert 9 + compressed_size == len(resource)
compressed = bytes((byte - resource[0]) % 256 for byte in resource[9:9 + compressed_size])
plain = lzokay.decompress(compressed, plain_size)
assert len(plain) == plain_size
author_resource = load(HERE / 'resources.json')
assert author_resource['key'] == resource[0]
assert author_resource['source_size'] == len(resource)
assert author_resource['source_sha256'] == hashlib.sha256(resource).hexdigest()
packed = bytes((byte - resource[0]) % 256 for byte in resource[1:])
assert author_resource['packed_size'] == len(packed)
assert author_resource['packed_sha256'] == hashlib.sha256(packed).hexdigest()
assert author_resource['compressed_size'] == compressed_size
assert author_resource['compressed_sha256'] == hashlib.sha256(compressed).hexdigest()
assert author_resource['decoded_size'] == plain_size
assert author_resource['decoded_sha256'] == hashlib.sha256(plain).hexdigest()
assert b''.join(bytes.fromhex(row['bytes']) for row in author_resource['lines']) == plain
cursor, independent_lines, independent_sections, independent_fields = 0, [], [], []
for number, line in enumerate(plain.splitlines(keepends=True), 1):
    independent_lines.append(dict(number=number, offset=cursor, size=len(line), bytes=line.hex()))
    content = line.rstrip(b'\r\n')
    match = re.fullmatch(rb'[ \t]*\[([^\]\r\n]+)\][ \t]*', content)
    if match:
        independent_sections.append(dict(index=len(independent_sections), line=number, offset=cursor,
                                         name_hex=match[1].hex(), ascii=match[1].decode('ascii')))
    elif b'=' in content:
        key, value = content.split(b'=', 1)
        independent_fields.append(dict(line=number, section_index=len(independent_sections) - 1,
                                       key_offset=cursor, key_hex=key.hex(),
                                       key_ascii=key.strip(b' \t').decode('ascii'),
                                       value_offset=cursor + len(key) + 1, value_hex=value.hex(),
                                       leading_space_trimmed_value_hex=value.lstrip(b' \t').hex()))
    cursor += len(line)
assert cursor == len(plain) and independent_lines == author_resource['lines']
assert independent_sections == author_resource['sections']
assert len(independent_fields) == len(author_resource['entries'])
assert author_resource['duplicate_keys'] == []
for ours, theirs in zip(independent_fields, author_resource['entries']):
    assert all(theirs[key] == value for key, value in ours.items())
assert {row['key_ascii']: bytes.fromhex(row['leading_space_trimmed_value_hex']).decode('ascii')
        for row in independent_fields} == {'enable': 'true', 'card': '200', 'avatar': '60', 'bout': '100'}

manifest = load(HERE.parent / 'function_review.json')
assert len(manifest['functions']) == 21
assert len({row['va'] for row in manifest['functions']}) == 21
assert sum(not row['reused'] for row in manifest['functions']) == 9
for row in manifest['functions']:
    assert row['conclusion'] and row['unknown'] and row['declared_chunks'] and row['original_byte_ranges']
    assert row['status'] != '仅导出'
    for pointer in row['evidence']:
        path = (ROOT / 'docs/逆向资料' if row['reused'] else HERE.parent) / pointer['path']
        original = load(path)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == pointer['sha256']
        record = next(f for f in original['functions'] if f['va'] == pointer['entry'])
        assert row['va'] == record['va']
        assert row['original_byte_ranges'] == (record.get('chunk_byte_ranges') or record.get('chunks') or record['byte_ranges'])
        declared = record.get('declared_chunks') or [dict(start_va=r['va'], end_va=r['end_va'], is_main=r['va'] == record['va'])
                                                    for r in record['chunks']]
        assert declared == row['declared_chunks']
validation = load(HERE / 'author_validation.json')
assert validation['status'] == 'PASS' and validation['disk_sha256'] == BASELINE
assert (validation['functions'], validation['fresh'], validation['reused']) == (21, 9, 12)
document_hashes = {}
for path in sorted(HERE.parent.glob('*.txt')):
    if path.name == '独立审阅.txt' and '--final' not in sys.argv:
        continue
    blob = path.read_bytes()
    assert all(not line.strip() or line.startswith('//') for line in blob.decode('utf-8').splitlines())
    document_hashes[path.name] = hashlib.sha256(blob).hexdigest()
if '--final' in sys.argv:
    assert '独立审阅.txt' in document_hashes and len(document_hashes) == 5

unique = {(va, size) for va, size, _ in comparisons}
result = dict(status='PASS', disk_sha256=BASELINE, functions=functions,
              byte_comparisons=len(comparisons), unique_spans=len(unique),
              unique_bytes=len({va + n for va, size in unique for n in range(size)}),
              instruction_sites=len(instructions), calls=list(calls.values()), unique_call_sites=len(calls),
              bridges=list(bridges.values()), unique_bridges=len(bridges), strings=strings,
              unique_function_entries=len({row['va'] for row in functions}), navigation_only=navigation_only,
              semantic_anchors={hex(va): instructions[va] for va in anchors}, card_x87_sequence=float_sequence,
              manifest=dict(functions=21, fresh=9, reused=12, sha256=input_hashes[(HERE.parent / 'function_review.json').relative_to(ROOT).as_posix()]),
              final='--final' in sys.argv, document_sha256=document_hashes,
              resource=dict(source_size=len(resource), source_sha256=hashlib.sha256(resource).hexdigest(),
                            packed_size=len(packed), packed_sha256=hashlib.sha256(packed).hexdigest(),
                            compressed_size=compressed_size, decoded_size=plain_size,
                            decoded_sha256=hashlib.sha256(plain).hexdigest(), decoded_hex=plain.hex(),
                            lines=independent_lines, sections=independent_sections, fields=independent_fields),
              input_sha256=input_hashes, scope='PE、声明块、调用、字符串及离线资源；语义审阅另记边界')
(HERE / 'independent_pe.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
lines = ['// PlusPrize 当前PE独立Capstone解码；来源复用不重复计入新增业务覆盖。']
for va, row in sorted(instructions.items()):
    lines.append(f"// {va:08X} {row['hex']:<30} {row['mnemonic']} {row['operands']}")
(HERE / 'independent_assembly.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(json.dumps({key: result[key] for key in ('status', 'byte_comparisons', 'unique_spans', 'unique_bytes',
                                              'instruction_sites', 'unique_call_sites', 'unique_bridges')}, ensure_ascii=False))
