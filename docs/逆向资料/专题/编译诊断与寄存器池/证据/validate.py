"""独立核对磁盘 PE 原证、声明块、跳板/导航和诊断/池的局部常量。"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import struct

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]
SHA = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
def load(name):
    return json.loads((BASE/name).read_text('utf-8'))
blob = (ROOT/'RnClient.exe').read_bytes()
assert hashlib.sha256(blob).hexdigest() == SHA
nt = struct.unpack_from('<I', blob, 0x3C)[0]
opt = nt+24
image_base = struct.unpack_from('<I', blob, opt+28)[0]
sections = []
for i in range(struct.unpack_from('<H', blob, nt+6)[0]):
    section = opt+struct.unpack_from('<H', blob, nt+20)[0]+40*i
    rva, size, offset = struct.unpack_from('<III', blob, section+12)
    sections.append((image_base+rva, size, offset))
def disk(a, n):
    for start, size, offset in sections:
        if start <= a and a+n <= start+size:
            return blob[offset+a-start:offset+a-start+n]
    raise AssertionError(('无磁盘原始区', hex(a), n))
checks = Counter()
def byte_record(record):
    raw = disk(int(record['va'], 16), record['size'])
    assert raw.hex() == record['idb_hex'] == record['disk_hex'] and record['matching'] is True
    checks['byte_records'] += 1
    return raw
sources = [load('functions_raw.json'), load('identity_callers.json')]
functions = [f for source in sources for f in source['functions']]
assert len(functions) == len({f['va'] for f in functions}) == 14
for source in sources:
    assert source['disk_sha256'] == SHA
    for thunk in source['thunks']:
        b = byte_record(thunk)
        a = int(thunk['va'], 16)
        assert b[0] == 0xE9 and (a+5+struct.unpack_from('<i', b, 1)[0]) & 0xFFFFFFFF == int(thunk['target'], 16)
for f in functions:
    assert f['bytes_match_disk'] is True
    for field in ['byte_ranges', 'chunk_byte_ranges']:
        for record in f[field]:
            byte_record(record)
    assert len(f['declared_chunks']) == len(f['chunk_byte_ranges'])
    for chunk, record in zip(f['declared_chunks'], f['chunk_byte_ranges']):
        assert record['va'] == chunk['start_va']
        assert record['size'] == int(chunk['end_va'], 16)-int(chunk['start_va'], 16)
    for ins in f['assembly']:
        a = int(ins['va'], 16)
        assert any(int(c['start_va'], 16) <= a < int(c['end_va'], 16) for c in f['declared_chunks'])
    for call in f['calls']:
        a = int(call['site'], 16)
        b = disk(a, 5)
        assert b[0] in (0xE8, 0xE9)
        assert (a+5+struct.unpack_from('<i', b, 1)[0]) & 0xFFFFFFFF == int(call['target'], 16)
    checks['instructions'] += len(f['assembly'])
    checks['chunks'] += len(f['declared_chunks'])
    checks['chunk_bytes'] += sum(r['size'] for r in f['chunk_byte_ranges'])
nav = load('navigation_data.json')
assert nav['disk_sha256'] == SHA
assert len(nav['targets']) == 9 and sum(len(t['references']) for t in nav['targets']) == 961
for target in nav['targets']:
    byte_record(target['thunk'])
    for reference in target['references']:
        b = byte_record(reference['bytes'])
        if b[0] in (0xE8, 0xE9):
            a = int(reference['site'], 16)
            assert (a+5+struct.unpack_from('<i', b, 1)[0]) & 0xFFFFFFFF == int(target['target'], 16)
            checks['navigation_relative_control'] += 1
        else:
            checks['navigation_other'] += 1
data = {int(r['va'], 16): r for r in nav['data_records']}
for record in data.values():
    b = byte_record(record)
    if 'ascii' in record:
        assert b == record['ascii'].encode('ascii')+b'\0'
assert disk(0xA51D70, 22) == b'D3DX9 Shader Compiler\0'
assert disk(0xA45020, 23) == b'D3DX9 Shader Assembler\0'
assert struct.unpack('<I', disk(0xA75FE4, 4))[0] == 0xA51D70
assert struct.unpack('<I', disk(0xA6DF58, 4))[0] == 0xA45020
assert struct.unpack('<d', disk(0xA3FF08, 8))[0] == 1e-6
assert struct.unpack('<d', disk(0xA2B480, 8))[0] == 0.0
assert struct.unpack('<d', disk(0xA226E0, 8))[0] == 1.0
asm = {int(f['va'], 16): '\n'.join(i['text'] for i in f['assembly']) for f in functions}
for va, tokens in {
    0x993EC8: ['rep stosd', 'retn    8', '0FFFFFFFFh'],
    0x9CAD79: ['60h', 'mov     edi, ecx', 'sub_60D44D', 'sub_6077A0'],
    0x9CAF88: ['jnb', '[ecx+8]', '[ecx+14h]'],
    0x9CAA68: ['400h', 'add     eax, eax', 'dbl_A3FF08', 'j___ftol'],
    0x9D0A78: ['100h', '[ebp+var_1]', '[esi+38h], 1', 'sub_60CDD1'],
    0x994DE3: ['100h', '[ebp+var_1]', '[esi+34h], 1', 'sub_60CDD1'],
    0x98E8C1: ['1000h', '0FFEh', '[esi+1]', '[ecx+8]', 'sub_60A333'],
    0x995011: ['30000001h', '30000002h', '25000001h', '24000001h', '80004005h', '8007000Eh', 'retn    18h'],
    0xA0B1AA: ['dword_A75FE4', 'sub_6092FD'],
    0x9916F1: ['dword_A6DF58', 'sub_60CDD1'],
}.items():
    for token in tokens:
        assert token in asm[va], (hex(va), token)
# 用独立期望表核对初始化写入覆盖，避免把保留的+5C误称已初始化。
init = next(f for f in functions if f['va'] == '0x9cb700')
written = set()
import re
for ins in init['assembly']:
    text = ins['text']
    match = re.search(r'(?:mov|fstp)\s+(?:qword ptr )?\[ecx(?:\+([0-9A-F]+)h)?\],', text)
    if match:
        offset = int(match.group(1) or '0', 16)
        written.add(offset)
        if 'qword ptr' in text:
            written.add(offset+4)
assert written == {0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,60,64,68,72,76,80,84,88}
assert 0x5C not in written
review = load('function_review.json')
assert review['counts'] == {'局部语义已审阅': 11, '部分分析': 3}
assert {f['va'] for f in review['functions']} == {f['va'] for f in functions}
for f in review['functions']:
    assert f['status'] == f['review_status'] and f['full_dependency_closure'] is False
    assert bool(f['reviewed_chunks']) == (f['review_status'] == '局部语义已审阅')
    assert f['conclusion'] and f['unknown'] and all((BASE/p).exists() for p in f['evidence'])
docs = sorted(BASE.parent.glob('*.txt'))
for path in docs:
    assert all(not line or line.startswith('//') for line in path.read_text('utf-8').splitlines())
result = dict(status='通过', disk_sha256=SHA, functions=len(functions), review_counts=review['counts'],
    documents=len(docs), checks=dict(checks), data_records=len(data), initialized_dword_offsets=sorted(written),
    caveat='原字节和局部常量验证；未证明真实资源触发路径及所有操作码语义')
(BASE/'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(json.dumps(result, ensure_ascii=True))
