# 只读核验当前 PE、IDA 原证字节、chunk 覆盖和资源哈希；不启动客户端。
from pathlib import Path
import hashlib
import json
import struct

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[3]
blob = (ROOT / 'RnClient.exe').read_bytes()
disk_sha = hashlib.sha256(blob).hexdigest()
pe = struct.unpack_from('<I', blob, 0x3c)[0]
assert blob[pe:pe + 4] == b'PE\0\0'
count = struct.unpack_from('<H', blob, pe + 6)[0]
opts = struct.unpack_from('<H', blob, pe + 20)[0]
imagebase = struct.unpack_from('<I', blob, pe + 52)[0]
sections = [struct.unpack_from('<IIII', blob, pe + 24 + opts + 40 * i + 8) for i in range(count)]
def disk(va, size):
    ea = int(va, 16)
    for vs, rva, rawsize, offset in sections:
        rel = ea - imagebase - rva
        if 0 <= rel and rel + size <= rawsize:
            return blob[offset + rel:offset + rel + size]
    raise ValueError('VA不在原始PE映射范围: ' + va)
def check(row):
    now = disk(row['va'], row['size']).hex()
    assert row['matching'] and row['idb_hex'] == row['disk_hex'] == now, row['va']

raw_names = [p.name for p in (BASE / '证据').glob('*.json')
             if p.name not in {'resources.json', 'binding_and_data.json'}]
functions, thunks = {}, {}
for name in raw_names:
    raw = json.loads((BASE / '证据' / name).read_text(encoding='utf-8'))
    assert raw['disk_sha256'] == disk_sha, name
    for f in raw.get('functions', []):
        assert f['bytes_match_disk'] and f.get('chunks'), f['va']
        for row in f['byte_ranges']:
            check(row)
        ranges = [(int(r['va'], 16), int(r['va'], 16) + r['size']) for r in f['byte_ranges']]
        for c in f['chunks']:
            lo, hi = int(c['start_va'], 16), int(c['end_va'], 16)
            assert any(a <= lo and hi <= b for a, b in ranges), (f['va'], c)
        if f['va'] in functions:
            assert f['byte_ranges'] == functions[f['va']]['byte_ranges'], f['va']
        functions[f['va']] = f
    for t in raw.get('thunks', []):
        check(t)
        thunks[t['va']] = t
binding = json.loads((BASE / '证据' / 'binding_and_data.json').read_text(encoding='utf-8'))
assert binding['disk_sha256'] == disk_sha
for row in binding['data_checks']:
    check(row)
for row in binding['registration']:
    raw = disk(row['site'], 10)
    assert raw[:2] == b'\xc7\x05'
    assert struct.unpack('<II', raw[2:]) == (int(row['slot'], 16), int(row['thunk'], 16))
assert len(binding['registration']) == 16 and len(binding['rtc']) == 16
for rtc in binding['rtc']:
    count, pointer = struct.unpack('<II', disk(rtc['descriptor'], 8))
    assert count == len(rtc['locals'])
    for index, row in enumerate(rtc['locals']):
        offset, size, name_va = struct.unpack('<iiI', disk(hex(pointer + 12 * index), 12))
        assert (offset, size, name_va) == (row['offset'], row['size'], int(row['name_va'], 16))
        assert disk(row['name_va'], len(row['name']) + 1) == row['name'].encode('ascii') + b'\0'
resources = json.loads((BASE / '证据' / 'resources.json').read_text(encoding='utf-8'))
for row in resources['records']:
    value = (ROOT / row['source']).read_bytes()
    assert len(value) == row['size'] and hashlib.sha256(value).hexdigest() == row['sha256']
reviews = json.loads((BASE / 'function_review.json').read_text(encoding='utf-8'))
assert {r['va'] for r in reviews['functions']} == set(functions)
for row in reviews['functions']:
    assert row['conclusion'] and row['unknown'] and row['evidence']
    for path in row['evidence']:
        assert (BASE / path).is_file(), path
result = dict(scope='仅核原证与当前PE/资源一致，不代表业务、界面或通信运行验证',
              disk_sha256=disk_sha, unique_function_count=len(functions),
              unique_function_bytes=sum(r['size'] for f in functions.values() for r in f['byte_ranges']),
              code_range_count=sum(len(f['byte_ranges']) for f in functions.values()),
              unique_thunk_count=len(thunks), data_check_count=len(binding['data_checks']),
              rtc_handler_count=len(binding['rtc']), resource_count=len(resources['records']),
              undeclared_range_count=len(binding.get('undeclared_ranges', [])),
              function_mismatches=[], thunk_mismatches=[], data_mismatches=[])
(BASE / '专题验证.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result, ensure_ascii=False))
