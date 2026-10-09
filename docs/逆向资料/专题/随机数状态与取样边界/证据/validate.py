"""独立PE映射核对导出与算术；不把导航项提升为语义审阅。"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import struct

BASE=Path(__file__).resolve().parent
PROJECT=BASE.parents[4]
blob=(PROJECT/'RnClient.exe').read_bytes()
digest=hashlib.sha256(blob).hexdigest()
assert digest=='a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2'
pe=struct.unpack_from('<I',blob,0x3c)[0]
assert blob[pe:pe+4]==b'PE\0\0'
assert struct.unpack_from('<H',blob,pe+24)[0]==0x10b
base=struct.unpack_from('<I',blob,pe+52)[0]
optional=struct.unpack_from('<H',blob,pe+20)[0]
sections=[]
for i in range(struct.unpack_from('<H',blob,pe+6)[0]):
    at=pe+24+optional+40*i
    rva,size,offset=struct.unpack_from('<III',blob,at+12)
    sections.append((base+rva,size,offset))
def disk(a,n):
    for start,size,offset in sections:
        if start<=a and a+n<=start+size:
            return blob[offset+a-start:offset+a-start+n]
    raise AssertionError(('无磁盘映射',hex(a),n))
def load(name):return json.loads((BASE/name).read_text('utf-8'))
checks=Counter()
def identity(r):
    got=disk(int(r['va'],16),r['size']).hex()
    assert got==r['idb_hex']==r['disk_hex'] and r['matching'],r['va']
    checks['byte_ranges']+=1
raw,nav,review,sim=(load(n) for n in ['functions_raw.json','reverse_navigation.json','function_review.json','simulation.json'])
assert raw['disk_sha256']==nav['disk_sha256']==digest
functions={f['va']:f for f in raw['functions']}
for f in functions.values():
    chunks=sorted((int(c['start_va'],16),int(c['end_va'],16)) for c in f['declared_chunks'])
    declared=sorted((int(r['va'],16),int(r['va'],16)+r['size']) for r in f['chunk_byte_ranges'])
    spans=sorted((int(r['va'],16),int(r['va'],16)+r['size']) for r in f['byte_ranges'])
    assert chunks==declared==spans,f['va']
    for r in f['chunk_byte_ranges']+f['byte_ranges']:identity(r)
    for ins in f['assembly']:
        assert any(start<=int(ins['va'],16)<end for start,end in chunks)
    assert len({i['va'] for i in f['assembly']})==len(f['assembly'])
    assert f['bytes_match_disk']
    checks['functions']+=1
    checks['chunks']+=len(chunks)
    checks['assembly_entries']+=len(f['assembly'])
    directives=sum(i['text'].lstrip().startswith(('align','db ','dw ','dd ')) for i in f['assembly'])
    checks['data_or_alignment_directives']+=directives
    checks['decoded_instruction_entries']+=len(f['assembly'])-directives
    checks['declared_bytes']+=sum(end-start for start,end in chunks)
for r in raw['thunks']+nav['address_taken_thunks']:
    identity(r)
    a=int(r['va'],16)
    b=disk(a,5)
    assert b[0]==0xe9 and a+5+int.from_bytes(b[1:],'little',signed=True)==int(r['target'],16)
for t in nav['targets']:
    for r in t['references']:
        assert r['bytes']['va']==r['site']
        identity(r['bytes'])
        a=int(r['site'],16)
        b=disk(a,r['size'])
        assert b[0] in (0xe8,0xe9) and len(b)==5
        assert a+5+int.from_bytes(b[1:],'little',signed=True)==int(t['target'],16)
        assert r['kind']==(17 if b[0]==0xe8 else 19)
        if r['function'] in functions:
            assert any(i['va']==r['site'] and i['text']==r['disassembly'] for i in functions[r['function']]['assembly'])
    checks['navigation_references']+=len(t['references'])
for r in nav['data_records']:
    identity(r)
    if 'text' in r:assert bytes.fromhex(r['disk_hex'])==r['text'].encode('ascii')+b'\0'
assert next(r for r in nav['data_records'] if r['va']=='0xa69d94')['disk_hex']=='ffffffff'
assert struct.unpack('<f',disk(0xa23388,4))[0]==100.0
assert disk(0x9208d2,6)==bytes.fromhex('69c9fd430300')
assert disk(0x9208d8,6)==bytes.fromhex('81c1c39e2600')
assert disk(0x9208ea,3)==bytes.fromhex('c1e810')
assert disk(0x9208ed,5)==bytes.fromhex('25ff7f0000')
assert disk(0x930950,7)==bytes.fromhex('c7411401000000')
assert disk(0x7eca7a,3)==bytes.fromhex('0fbfc0')
assert set(functions)=={r['va'] for r in review['functions']}
counts=dict(Counter(r['review_status'] for r in review['functions']))
assert counts==review['counts']=={'局部语义已审阅':13,'部分分析':5,'复用已有审阅':4}
for r in review['functions']:
    assert r['conclusion'] and r['unknown']
    if r['review_status']=='局部语义已审阅':assert r['reviewed_chunks']==functions[r['va']]['declared_chunks']
    else:assert r['reviewed_chunks']==[]
for vector in sim['lcg_vectors']:
    s=int(vector['seed'],16)
    for expected,state in zip(vector['outputs'],vector['states']):
        s=(s*0x343fd+0x269ec3)&0xffffffff
        assert s==int(state,16) and expected==(s>>16)&0x7fff
for h in sim['modulo_support_histograms']:
    n=h['modulus']
    q,k=divmod(32768,n)
    assert (h['quotient'],h['remainder'],h['reachable'])==(q,k,min(n,32768))
    assert h['max_count']==q+bool(k)
    assert h['min_count']==q
assert sim['display_alphabet']=='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
assert sim['interval_boundaries'][2]['exception']
assert sim['interval_boundaries'][5]['max']==32767
rand=next(t for t in nav['targets'] if t['target']=='0x60ae14')
assert len(rand['references'])==90
assert sum(r['function'] is None for r in rand['references'])==25
assert len({r['function'] for r in rand['references'] if r['function']})==38
for source in load('reuse_manifest.json')['sources']:
    assert hashlib.sha256((PROJECT/source['path']).read_bytes()).hexdigest()==source['sha256']
docs=list(BASE.parent.glob('*.txt'))
for path in docs:
    for line in path.read_text('utf-8').splitlines():assert not line.strip() or line.startswith('//'),path.name
result=dict(status='通过',disk_sha256=digest,checks=dict(checks),review_counts=counts,
            data_records=len(nav['data_records']),documents=len(docs),
            scope='静态证据一致性与离线模型；未运行EXE，不证明真实调用者参数及实机概率')
(BASE/'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=True))
