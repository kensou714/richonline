"""独立重读PE字节，检查结构导航、导出块覆盖、跳板与审阅口径。"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import struct

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[4]
blob = (ROOT / 'RnClient.exe').read_bytes()
digest = hashlib.sha256(blob).hexdigest()
assert digest == 'a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
pe = struct.unpack_from('<I', blob, 60)[0]
assert blob[pe:pe+4] == b'PE\0\0'
assert struct.unpack_from('<H', blob, pe+24)[0] == 0x10b
count = struct.unpack_from('<H', blob, pe+6)[0]
optional = struct.unpack_from('<H', blob, pe+20)[0]
image_base = struct.unpack_from('<I', blob, pe+52)[0]
sections = []
for i in range(count):
    p = pe + 24 + optional + 40*i
    rva, size, offset = struct.unpack_from('<III', blob, p+12)
    flags = struct.unpack_from('<I', blob, p+36)[0]
    sections.append((image_base+rva, size, offset, flags))

def disk(va, size):
    for start, n, off, flags in sections:
        if start <= va and va + size <= start+n:
            return blob[off+va-start:off+va-start+size]
    raise AssertionError('无磁盘映射 ' + hex(va))

def words(va, n):
    return struct.unpack('<'+'I'*n, disk(va, n*4))

def code(va):
    return any(start <= va < start+n and flags & 0x20000000 for start,n,off,flags in sections)

def signed(v):
    return v - 0x100000000 if v >= 0x80000000 else v

def load(name):
    return json.loads((BASE/name).read_text('utf-8'))

checks = Counter()
def identity(row, live=True):
    got = disk(int(row['va'],16), row['size']).hex()
    assert got == row['disk_hex'], row['va']
    if live:
        assert row['matching'] and got == row['idb_hex'], row['va']
    checks['byte_ranges'] += 1

scan, nav, raw, review = (load(n) for n in ['rtti_scan.json','ida_navigation.json','functions_raw.json','function_review.json'])
for source in [scan, nav, raw]:
    assert source['disk_sha256'] == digest
tds = {int(t['va'],16):t for t in scan['type_descriptors']}
for address, t in tds.items():
    assert words(address,2) == (int(t['type_info_vtable'],16),t['spare'])
    name = t['decorated_name'].encode('ascii')+b'\0'
    assert disk(address+8,len(name)) == name
    assert name.startswith((b'.?AV',b'.?AU')) and name.endswith(b'@@\0')
    assert code(words(int(t['type_info_vtable'],16),1)[0])
for h in scan['hierarchies']:
    address = int(h['va'],16)
    assert words(address,4) == (h['signature'],h['attributes'],h['base_count'],int(h['base_array'],16))
    assert h['signature']==0 and h['attributes']==0 and len(h['bases'])==h['base_count']
    assert words(int(h['base_array'],16),h['base_count']) == tuple(int(b['va'],16) for b in h['bases'])
    for b in h['bases']:
        values = words(int(b['va'],16),6)
        assert values[:2] == (int(b['type_descriptor'],16),b['contained_bases'])
        assert values[0] in tds
        assert [signed(v) for v in values[2:5]] == [b['pmd'][k] for k in ['mdisp','pdisp','vdisp']]
        assert values[5] == b['attributes'] == 0
        checks['bcd_occurrences'] += 1
    assert h['bases'][0]['contained_bases']==h['base_count']-1
hs = {h['va']:h for h in scan['hierarchies']}
cols = {c['va']:c for c in scan['locators']}
for c in cols.values():
    assert words(int(c['va'],16),5)==(c['signature'],c['offset'],c['cd_offset'],int(c['type_descriptor'],16),int(c['hierarchy'],16))
    assert c['signature']==c['offset']==c['cd_offset']==0
    assert hs[c['hierarchy']]['bases'][0]['type_descriptor']==c['type_descriptor']
for v in scan['vftables']+scan['heuristic_arrays']:
    address = int(v['va'],16)
    entries = v['entries']
    assert [int(e['slot'],16) for e in entries]==[address+4*i for i in range(len(entries))]
    assert words(address,len(entries)) == tuple(int(e['target'],16) for e in entries)
    assert all(code(int(e['target'],16)) for e in entries)
    assert not code(words(address+4*len(entries),1)[0])
    if 'locator' in v:
        assert words(address-4,1)[0] == int(v['locator'],16)
        assert v['type_descriptor'] == cols[v['locator']]['type_descriptor']
    else:
        assert len(entries)>=3 and words(address-4,1)[0]==int(v['preceding_dword'],16)
for r in scan['data_records']:
    identity(r,False)
assert len(scan['data_records'])==len(nav['data_records'])
for r in nav['data_records']+nav['supplemental_data']:
    identity(r)
for r in nav['rejected_col_samples']:
    identity(r['bytes'])
    assert int(r['reference_site'],16)-12==int(r['candidate_col'],16)
    assert words(int(r['candidate_col'],16)+12,1)[0] == int(r['type_descriptor'],16)
assert len(nav['rejected_col_samples'])==len(scan['rejected_col_candidates'])==28
assert nav['supplemental_data'][0]['fields']==[-1,0,0x921196]
thunks = {}
for r in raw['thunks']:
    identity(r)
    a=int(r['va'],16)
    b=disk(a,5)
    assert b[0]==0xe9 and a+5+int.from_bytes(b[1:],'little',signed=True)==int(r['target'],16)
    thunks[a]=r
functions={f['va']:f for f in raw['functions']}
for f in functions.values():
    chunks=sorted((int(c['start_va'],16),int(c['end_va'],16)) for c in f['declared_chunks'])
    spans=sorted((int(r['va'],16),int(r['va'],16)+r['size']) for r in f['chunk_byte_ranges'])
    assert chunks==spans, f['va']
    for r in f['chunk_byte_ranges']+f['byte_ranges']:
        identity(r)
    code_ranges=sorted((int(r['va'],16),int(r['va'],16)+r['size']) for r in f['byte_ranges'])
    assert code_ranges==chunks, ('未解释字节空洞',f['va'])
    for ins in f['assembly']:
        a=int(ins['va'],16)
        assert any(start<=a<end for start,end in chunks)
    assert len({i['va'] for i in f['assembly']})==len(f['assembly'])
    assert f['bytes_match_disk']
    checks['functions']+=1
    checks['chunks']+=len(chunks)
    checks['instructions']+=len(f['assembly'])
for v in nav['vtable_references']:
    identity(v['preceding_slot'])
    for i,t in enumerate(v['targets']):
        assert words(int(v['vtable'],16)+4*i,1)[0]==int(t['entry'],16)
        current=int(t['entry'],16)
        for j in t['jumps']:
            identity(j)
            assert int(j['va'],16)==current
            b=disk(current,5)
            assert b[0]==0xe9
            current+=5+int.from_bytes(b[1:],'little',signed=True)
            assert current==int(j['target'],16)
        assert current==int(t['implementation'],16)
    for x in v['references']:
        if x['bytes'] is not None:
            identity(x['bytes'])
        if x['function']:
            assert x['function'] in functions
            assert any(i['va']==x['source'] and i['text']==x['instruction'] for i in functions[x['function']]['assembly'])
assert set(functions)=={r['va'] for r in review['functions']}
counts=dict(Counter(r['review_status'] for r in review['functions']))
assert counts==review['counts']=={'局部语义已审阅':56,'复用已有审阅':4,'仅导航':8}
for r in review['functions']:
    assert r['conclusion'] and r['unknown']
    if r['review_status']=='局部语义已审阅':
        assert r['reviewed_chunks']==functions[r['va']]['declared_chunks']
    else:
        assert r['reviewed_chunks']==[]
docs=list(BASE.parent.glob('*.txt'))
for path in docs:
    for n,line in enumerate(path.read_text('utf-8').splitlines(),1):
        assert not line.strip() or line.startswith('//'),(path.name,n)
for source in load('reuse_manifest.json')['sources']:
    assert hashlib.sha256((ROOT/source['path']).read_bytes()).hexdigest()==source['sha256'],source['path']
result=dict(status='通过',disk_sha256=digest,checks=dict(checks),review_counts=counts,
            type_descriptors=len(tds),col_chains=len(cols),heuristic_arrays=len(scan['heuristic_arrays']),
            documents=len(docs),scope='静态归档一致性；候选/导出不升级为语义审阅，实时IDA另核')
(BASE/'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=True))
