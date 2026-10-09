"""重新只读当前PE，核归档函数字节/跳板/数据/资源；不启动客户端或模拟通信。"""
from pathlib import Path
import hashlib
import json
import struct

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[3]
blob = (ROOT/'RnClient.exe').read_bytes()
disk_sha = hashlib.sha256(blob).hexdigest()
pe = struct.unpack_from('<I',blob,0x3C)[0]
assert blob[pe:pe+4] == b'PE\0\0'
count, opts = struct.unpack_from('<H',blob,pe+6)[0], struct.unpack_from('<H',blob,pe+20)[0]
imagebase = struct.unpack_from('<I',blob,pe+52)[0]
sections = [struct.unpack_from('<IIII',blob,pe+24+opts+40*i+8) for i in range(count)]
def disk(va, size):
    ea = int(va,16)
    for vs,rva,rawsize,offset in sections:
        relative=ea-imagebase-rva
        if 0 <= relative and relative+size <= rawsize:
            return blob[offset+relative:offset+relative+size]
    raise ValueError('VA不在原始PE映射范围: '+va)
def check(row):
    now = disk(row['va'],row['size']).hex()
    assert row['matching'] and row['idb_hex'] == row['disk_hex'] == now, row['va']
functions, thunks = {}, {}
raw_files = ['handlers.json','helpers.json','consumers.json','ui_and_slots.json','ui_callbacks.json']
for name in raw_files:
    raw=json.loads((BASE/'证据'/name).read_text(encoding='utf-8'))
    assert raw['disk_sha256'] == disk_sha
    for f in raw['functions']:
        assert f['bytes_match_disk']
        for r in f['byte_ranges']: check(r)
        assert f['chunks']
        for chunk in f['chunks']:
            start, end = int(chunk['start_va'],16), int(chunk['end_va'],16)
            ranges = [(int(r['va'],16),int(r['va'],16)+r['size']) for r in f['byte_ranges']]
            assert any(lo <= start and hi >= end for lo,hi in ranges), (f['va'],chunk)
        if f['va'] in functions:
            assert f['byte_ranges'] == functions[f['va']]['byte_ranges']
        functions[f['va']] = f
    for t in raw['thunks']:
        check(t)
        thunks[t['va']]=t
binding=json.loads((BASE/'证据/binding_and_capacity.json').read_text(encoding='utf-8'))
assert binding['disk_sha256'] == disk_sha
for r in binding['data_checks']: check(r)
assert binding['data_checks'][0]['va'] == '0x7ee85b' and binding['data_checks'][0]['size'] == 30
for row in binding['registration']:
    raw = disk(row['site'],10)
    assert raw[:2] == b'\xC7\x05'
    assert struct.unpack('<II',raw[2:]) == (int(row['slot'],16),int(row['thunk'],16))
assert binding['rotation_table'] == [1,2,6,14,600]
assert struct.unpack('<5I',disk('0xa2d2c8',20)) == (1,2,6,14,600)
assert [r['size'] for r in binding['rtc'][0]['locals']] == [128,4,24,4]
resources=json.loads((BASE/'证据/resources.json').read_text(encoding='utf-8'))
for r in resources['records']:
    value=(ROOT/r['source']).read_bytes()
    assert len(value) == r['size'] and hashlib.sha256(value).hexdigest() == r['sha256']
reviews=json.loads((BASE/'function_review.json').read_text(encoding='utf-8'))
assert {r['va'] for r in reviews['functions']} == set(functions)
for r in reviews['functions']:
    assert r['conclusion'] and r['unknown'] and r['evidence']
    for path in r['evidence']: assert (BASE/path).is_file()
result = dict(scope='仅核原证与当前PE/资源一致，不代表业务、界面或通信运行验证',
              disk_sha256=disk_sha,unique_function_count=len(functions),
              unique_function_bytes=sum(r['size'] for f in functions.values() for r in f['byte_ranges']),
              unique_thunk_count=len(thunks),data_check_count=len(binding['data_checks']),
              resource_count=len(resources['records']),function_mismatches=[],thunk_mismatches=[],data_mismatches=[])
(BASE/'专题验证.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=False))
