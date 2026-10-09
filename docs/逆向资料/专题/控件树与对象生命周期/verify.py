"""只读核对当前PE、完整chunks、虚表跳板和链字段写者。"""
from pathlib import Path
from collections import Counter
import json
import hashlib
import struct

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[3]
blob = (ROOT / 'RnClient.exe').read_bytes()
sha = hashlib.sha256(blob).hexdigest()
pe = struct.unpack_from('<I', blob, 0x3c)[0]
count = struct.unpack_from('<H', blob, pe + 6)[0]
opts = struct.unpack_from('<H', blob, pe + 20)[0]
imagebase = struct.unpack_from('<I', blob, pe + 52)[0]
sections = [struct.unpack_from('<IIII', blob, pe + 24 + opts + 40*i + 8) for i in range(count)]
def disk(va, size):
    ea = int(va, 16) if isinstance(va, str) else va
    for vs, rva, rawsize, off in sections:
        rel = ea - imagebase - rva
        if 0 <= rel and rel + size <= rawsize:
            return blob[off + rel:off + rel + size]
    raise ValueError(hex(ea))
def check(row):
    assert row['matching'] and disk(row['va'], row['size']).hex() == row['idb_hex'] == row['disk_hex'], row['va']
raw_names = ['创建与链表.json', '几何传播.json', '状态与销毁.json', '名称调用复用.json']
functions, thunks = {}, {}
for name in raw_names:
    raw = json.loads((BASE / '证据' / name).read_text(encoding='utf-8'))
    assert raw['disk_sha256'] == sha
    for f in raw['functions']:
        assert f['bytes_match_disk'] and f['declared_chunks']
        for row in f['byte_ranges'] + f['chunk_byte_ranges']:
            check(row)
        assert {(c['start_va'], int(c['end_va'],16)-int(c['start_va'],16)) for c in f['declared_chunks']} == {(r['va'],r['size']) for r in f['chunk_byte_ranges']}
        functions[f['va']] = f
    for row in raw['thunks']:
        check(row)
        thunks[row['va']] = row
data = json.loads((BASE / '证据/链字段与虚表数据.json').read_text(encoding='utf-8'))
assert data['disk_sha256'] == sha
for row in data['data_checks'] + data['writer_checks'] + data['vtable_thunk_checks']:
    check(row)
for row in data['virtual_mapping']:
    entry = struct.unpack('<I', disk(0xa305ac + row['offset'], 4))[0]
    assert entry == int(row['entry'], 16)
    code = disk(entry, 5)
    assert code[0] == 0xe9 and entry + 5 + struct.unpack('<i', code[1:])[0] == int(row['implementation'], 16)
text = lambda va: '\n'.join(r['text'] for r in functions[hex(va)]['assembly'])
assert 'mov     edi, ecx' in text(0x8e2b50) and text(0x8e2b50).count('mov     eax, edi') == 2
assert '[esi+194h]' in text(0x8ea680) and '[esi+198h]' in text(0x8ea680) and '[eax+78h]' in text(0x8ea680)
assert 'call    dword ptr [eax]' in text(0x8e39d0) and 'call    dword ptr [edx]' in text(0x8e39d0)
writers = json.loads((BASE / '证据/链字段写者候选.json').read_text(encoding='utf-8'))['writers']
assert {r['function'] for r in writers} == {'0x8e0af0','0x8e0ed0','0x8e22c0','0x8e23f0','0x8e2d10','0x8e3750'}
assert {r['va'] for r in writers} == {r['va'] for r in data['writer_checks']}
callers = data['name_lookup_direct_callers']
assert len(callers) == 15 and Counter(r['function'] for r in callers) == {'0x8e3a70':7,'0x8e3eb0':7,'0x8e8800':1}
for va in [0x8e3a70, 0x8e3eb0, 0x8e8800]:
    lines = [line for line in functions[hex(va)]['pseudocode'] if 'sub_610D96(' in line]
    assert len(lines) == (1 if va == 0x8e8800 else 7) and all('a2: 0)' in line for line in lines)
review = json.loads((BASE / 'function_review.json').read_text(encoding='utf-8'))
assert {r['va'] for r in review['functions']} == set(functions)
for row in review['functions']:
    assert row['status'] and row['conclusion'] and row['unknown'] and row['evidence']
    for path in row['evidence']:
        assert (BASE / path).is_file()
for path in BASE.glob('*.txt'):
    assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines()), path.name
result = dict(scope='静态字节/映射一致性；非动态安全证明', disk_sha256=sha, functions=len(functions),
              declared_code_ranges=sum(len(f['chunk_byte_ranges']) for f in functions.values()),
              function_bytes=sum(r['size'] for f in functions.values() for r in f['chunk_byte_ranges']),
              thunks=len(thunks), data_regions=len(data['data_checks']), virtual_slots=len(data['virtual_mapping']),
              explicit_ui_chain_writers=len(writers), statuses=dict(Counter(r['status'] for r in review['functions'])))
(BASE / '专题验证.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(json.dumps(result, ensure_ascii=False))
