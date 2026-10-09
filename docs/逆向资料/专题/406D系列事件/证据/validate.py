"""只读对照当前PE、注册、跳板和资源；同时检查审阅清单及中文注释式文档。"""
from pathlib import Path
import hashlib
import json
import struct

BASE = Path(__file__).parent
ROOT = BASE.parents[4]
blob = (ROOT / 'RnClient.exe').read_bytes()
sha = hashlib.sha256(blob).hexdigest()
pe = struct.unpack_from('<I', blob, 0x3c)[0]
base = struct.unpack_from('<I', blob, pe+52)[0]
opt = struct.unpack_from('<H', blob, pe+20)[0]
sections = [struct.unpack_from('<IIII', blob, pe+24+opt+40*i+8)
            for i in range(struct.unpack_from('<H', blob, pe+6)[0])]
def disk(va, size):
    for _,rva,rawsize,offset in sections:
        relative = va-base-rva
        if 0 <= relative and relative+size <= rawsize:
            return blob[offset+relative:offset+relative+size]
    return None
def load(name):
    return json.loads((BASE / name).read_text(encoding='utf-8'))
def check(record, hexkey='idb_hex'):
    current = disk(int(record['va'],16), record['size'])
    assert current is not None, record['va']
    assert current.hex() == record[hexkey], record['va']
    if 'disk_hex' in record:
        assert current.hex() == record['disk_hex'], record['va']

review = load('function_review.json')
vas, thunks, byte_count = set(), {}, 0
source_hashes = {}
for source in review['sources']:
    data = load(source)
    assert data['disk_sha256'].lower() == sha
    source_hashes[source] = hashlib.sha256((BASE / source).read_bytes()).hexdigest()
    for f in data['functions']:
        assert f['pseudocode'] and f['assembly'] and f['byte_ranges'], (source,f['va'])
        assert f['declared_chunks'], (source,f['va'],'缺少显式块清单')
        for ins in f['assembly']:
            addr = int(ins['va'],16)
            assert any(int(c['start_va'],16) <= addr < int(c['end_va'],16) for c in f['declared_chunks'])
            assert any(int(r['va'],16) <= addr < int(r['va'],16)+r['size'] for r in f['byte_ranges'])
        for record in f['byte_ranges']:
            check(record)
            if f['va'] not in vas:
                byte_count += record['size']
        vas.add(f['va'])
    for record in data['thunks']:
        check(record)
        raw = bytes.fromhex(record['idb_hex'])
        assert raw[0] == 0xe9
        assert int(record['va'],16)+5+int.from_bytes(raw[1:], 'little', signed=True) == int(record['target'],16)
        thunks[record['va']] = record
assert vas == {f['va'] for f in review['functions']}
tail_audit = load('tail_chunk_audit.json')
assert tail_audit['functions_checked'] == len(vas)
for changed in tail_audit['changed_functions']:
    f = next(f for f in load(changed['source'])['functions'] if f['va'] == changed['va'])
    assert changed['new_bytes'] == sum(r['size'] for r in f['byte_ranges'])
    assert all(i in f['assembly'] for i in changed['added_assembly'])
binding = load('binding.json')
expected = set(range(0x406d,0x4080)) | {0x6000,0x6002,0x6003,0x6060,0x6080}
assert {int(e['code'],16) for e in binding['entries']} == expected
binding_checks = 0
for entry in binding['entries']:
    for key in ['thunk_audit','handler_thunk_audit','registration_write_audit']:
        check(entry[key], 'idb_bytes')
        assert entry[key]['idb_bytes'] == entry[key]['disk_bytes']
        binding_checks += 1
    write = bytes.fromhex(entry['registration_write_audit']['idb_bytes'])
    assert write[:2] == b'\xc7\x05'
    assert int.from_bytes(write[2:6],'little') == int(entry['slot'],16)
    assert int.from_bytes(write[6:10],'little') == int(entry['thunk'],16)
data_checks, unmapped = 0, []
for record in load('data_audit.json')['records']:
    if record['disk_hex'] is None:
        assert disk(int(record['va'],16),record['size']) is None
        unmapped.append(record['va'])
    else:
        check(record)
        data_checks += 1
for record in load('data_audit.json')['virtual_thunks']:
    check(record)
    assert int.from_bytes(disk(int(record['slot'],16),4),'little') == int(record['va'],16)
    raw = bytes.fromhex(record['idb_hex'])
    assert raw[0] == 0xe9
    assert int(record['va'],16)+5+int.from_bytes(raw[1:],'little',signed=True) == int(record['target'],16)
for record in load('resource_provenance.json'):
    assert hashlib.sha256((ROOT / record['source']).read_bytes()).hexdigest() == record['source_sha256']
    assert hashlib.sha256((BASE / record['output']).read_bytes()).hexdigest() == record['decoded_sha256']
docs = list(BASE.parent.glob('*.txt'))
for path in docs:
    assert all(not line.strip() or line.startswith('//') for line in path.read_text(encoding='utf-8').splitlines()), path
result = dict(status='通过', disk_sha256=sha, unique_functions=len(vas), unique_function_bytes=byte_count,
    unique_thunks=len(thunks), binding_entries=len(binding['entries']), binding_byte_checks=binding_checks,
    data_checks=data_checks, virtual_thunk_checks=4, unmapped_data=unmapped, resources=3, documents=len(docs),
    review_counts=review['counts'], source_hashes=source_hashes,
    tail_chunk_audit=dict(functions_checked=len(vas), changed_functions=len(tail_audit['changed_functions']),
        added_bytes=sum(r['new_bytes']-r['old_bytes'] for r in tail_audit['changed_functions'])),
    runtime_validation=False, full_dependency_closure=False)
(BASE / 'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=True))
