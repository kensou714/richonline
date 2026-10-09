"""独立对照当前PE验证证据；只写本专题验证报告，不修改客户端或IDB。"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import struct

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]
EXPECTED_SHA256 = 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
blob = (ROOT / 'RnClient.exe').read_bytes()
sha256 = hashlib.sha256(blob).hexdigest()
assert sha256 == EXPECTED_SHA256, '客户端版本变化，须重新进行IDA取证'
pe = struct.unpack_from('<I', blob, 0x3c)[0]
assert blob[:2] == b'MZ' and blob[pe:pe+4] == b'PE\0\0'
image_base = struct.unpack_from('<I', blob, pe + 52)[0]
count = struct.unpack_from('<H', blob, pe + 6)[0]
optional_size = struct.unpack_from('<H', blob, pe + 20)[0]
sections = []
for index in range(count):
    offset = pe + 24 + optional_size + index * 40
    virtual_size, rva, raw_size, raw_offset = struct.unpack_from('<IIII', blob, offset + 8)
    sections.append((rva, virtual_size, raw_size, raw_offset))

def load(name):
    return json.loads((BASE / name).read_text(encoding='utf-8'))

def disk_bytes(va, size):
    for rva, _, raw_size, offset in sections:
        relative = va - image_base - rva
        if 0 <= relative and relative + size <= raw_size:
            return blob[offset + relative:offset + relative + size]
    return None

def audit(record, allow_unmapped=False):
    va, size = int(record['va'], 16), record['size']
    original = bytes.fromhex(record.get('idb_hex', record.get('idb_bytes', '')))
    recorded = record.get('disk_hex', record.get('disk_bytes'))
    disk = disk_bytes(va, size)
    assert size > 0 and len(original) == size, record['va']
    if disk is None:
        assert allow_unmapped and recorded is None and record['matching'] is None
        assert any(0 <= va-image_base-rva and va-image_base-rva+size <= vs
                   for rva, vs, _, _ in sections), record['va']
    else:
        assert disk == original == bytes.fromhex(recorded), record['va']
        assert record['matching'] is True, record['va']
    return va, va + size

def thunk(record, target):
    va, _ = audit(record)
    raw = disk_bytes(va, 5)
    assert len(raw) == 5 and raw[0] == 0xe9, record['va']
    assert va + 5 + int.from_bytes(raw[1:], 'little', signed=True) == int(target, 16)

review = load('function_review.json')
unique = {}
function_entries = 0
thunk_entries = 0
for source in review['sources']:
    data = load(source)
    assert data['disk_sha256'] == sha256
    for f in data['functions']:
        function_entries += 1
        unique.setdefault(f['va'], []).append(source)
        assert f['pseudocode'] and f['assembly'] and f['bytes_match_disk'] is True, f['va']
        chunks = [(int(c['start_va'],16), int(c['end_va'],16)) for c in f['declared_chunks']]
        assert any(start == int(f['va'],16) for start, _ in chunks)
        spans = [audit(r) for r in f['byte_ranges']]
        assert all(any(cs <= start < end <= ce for cs, ce in chunks) for start, end in spans)
        addresses = [int(ins['va'],16) for ins in f['assembly']]
        assert len(addresses) == len(set(addresses))
        assert all(any(start <= address < end for start,end in spans) for address in addresses)
        assert all(any(address == start for address in addresses) for start,_ in spans)
    for record in data['thunks']:
        thunk(record, record['target'])
        thunk_entries += 1
assert {f['va']:f['sources'] for f in review['functions']} == unique
assert review['counts'] == dict(Counter(f['review_status'] for f in review['functions']))

binding = load('binding.json')['entries']
expected_codes = set(range(0x40c7,0x40d0)) | {0x6000,0x6001,0x6003,0x6005,0x6006,0x6007,0x6061,0x606b,0x6078,0x6079}
assert {int(e['code'],16) for e in binding} == expected_codes and len(binding) == 19
for entry in binding:
    thunk(entry['thunk_audit'], entry['bridge'])
    thunk(entry['handler_thunk_audit'], entry['handler'])
    write = entry['registration_write_audit']
    audit(write)
    raw = disk_bytes(int(write['va'],16), 10)
    assert raw == b'\xc7\x05'+struct.pack('<II',int(entry['slot'],16),int(entry['thunk'],16))
    assert entry['handler'] in unique and entry['template_verified'] is True

data = load('data_audit.json')
for record in data['records']:
    audit(record, allow_unmapped=True)
for record in data['virtual_thunks']:
    thunk(record, record['target'])
    assert struct.unpack('<I', disk_bytes(int(record['slot'],16),4))[0] == int(record['va'],16)
ranges = load('undeclared_ranges.json')['ranges']
assert len(ranges) == 3
for record in ranges:
    assert record['function_declared'] is False and record['va'] not in unique
    start, end = int(record['va'],16), int(record['end_va'],16)
    spans = [audit(r) for r in record['byte_ranges']]
    assert spans == [(start,end)]
    assert all(start <= int(ins['va'],16) < end for ins in record['assembly'])

resources = load('resource_provenance.json')
for resource in resources:
    assert hashlib.sha256((ROOT/resource['source']).read_bytes()).hexdigest() == resource['source_sha256']
    assert hashlib.sha256((BASE/resource['output']).read_bytes()).hexdigest() == resource['decoded_sha256']
documents = sorted(BASE.parent.glob('*.txt'))
for document in documents:
    for number,line in enumerate(document.read_text(encoding='utf-8').splitlines(),1):
        assert not line.strip() or line.startswith('//'), (document.name,number)
result = dict(disk_sha256=sha256, passed=True, unique_declared_functions=len(unique),
              function_entries=function_entries, review_status_counts=review['counts'],
              thunk_entries=thunk_entries, binding_entries=len(binding),
              data_records=len(data['records']), virtual_thunks=len(data['virtual_thunks']),
              undeclared_ranges=len(ranges), resource_files=len(resources), documents=len(documents),
              runtime_validation=False, full_dependency_closure=False,
              external_review_report='独立审阅.txt', review_not_evaluated_by_this_validator=True,
              limitation='静态原证与当前PE一致；不把字节校验视为业务语义或运行行为验证。')
(BASE/'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=True))
